// cfg-test observations of the existing supervisor's actual task owners.
// No network state, publication permission or replacement worker is stored.
#[derive(Default)]
struct C01UdpOwnersForTest {
    state: std::sync::Mutex<C01UdpOwnerState>,
}

#[derive(Default)]
struct C01UdpOwnerState {
    instances: [C01UdpInstance; 2],
    started: usize,
    shape_error: Option<String>,
}

#[derive(Default)]
struct C01UdpInstance {
    spawned: [Option<tokio::task::Id>; 4],
    joined: [bool; 4],
    join_errors: [Option<String>; 4],
    withdrawn: bool,
    child_sets: [Option<usize>; 2],
    child_errors: [Option<String>; 2],
}

#[derive(Clone)]
struct C01UdpInstanceForTest {
    owner: Arc<C01UdpOwnersForTest>,
    index: usize,
}

impl C01UdpOwnersForTest {
    fn begin(self: &Arc<Self>) -> C01UdpInstanceForTest {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let index = state.started;
        state.started = state.started.saturating_add(1);
        if index >= state.instances.len() {
            state.shape_error = Some("original supervisor exceeded two fixture instances".into());
        }
        C01UdpInstanceForTest {
            owner: self.clone(),
            index,
        }
    }

    fn handover_shape_is_complete(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.started == 2
            && state
                .instances
                .iter()
                .all(|instance| instance.spawned.iter().all(Option::is_some))
    }

    fn cleanup_report(&self) -> std::result::Result<String, String> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(error) = &state.shape_error {
            return Err(error.clone());
        }
        let mut total = 0;
        let mut drained = 0;
        let mut sets = 0;
        for (index, instance) in state.instances.iter().take(state.started).enumerate() {
            if !instance.withdrawn {
                return Err(format!(
                    "instance{index} did not actually clear its publication owner"
                ));
            }
            for slot in 0..4 {
                if instance.spawned[slot].is_none() {
                    continue;
                }
                if !instance.joined[slot] {
                    return Err(format!("instance{index} original worker{slot} not joined"));
                }
                if let Some(error) = &instance.join_errors[slot] {
                    return Err(error.clone());
                }
                total += 1;
            }
            for slot in 0..2 {
                if instance.spawned[if slot == 0 { 0 } else { 2 }].is_none() {
                    continue;
                }
                sets += 1;
                if let Some(error) = &instance.child_errors[slot] {
                    return Err(error.clone());
                }
                drained += instance.child_sets[slot].ok_or_else(|| {
                    format!("instance{index} original child set{slot} not drained")
                })?;
            }
        }
        Ok(format!("instances={} original_workers_joined={total}/{total} pending_children_joined={drained} original_child_sets_drained={sets}/{sets}", state.started))
    }
}

impl C01UdpInstanceForTest {
    fn withdrawn(&self, actually_cleared: bool) {
        let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(instance) = state.instances.get_mut(self.index) {
            instance.withdrawn = actually_cleared;
        }
    }

    fn spawned(&self, slot: usize, id: tokio::task::Id) {
        let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(instance) = state.instances.get_mut(self.index) else {
            return;
        };
        if instance.spawned[slot].replace(id).is_some() {
            instance.join_errors[slot] = Some("original worker slot reused".into());
        }
    }

    fn joined(&self, slot: usize, id: tokio::task::Id, error: Option<String>) {
        let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(instance) = state.instances.get_mut(self.index) else {
            return;
        };
        if instance.spawned[slot] != Some(id) || instance.joined[slot] {
            instance.join_errors[slot] = Some("join did not match its one original task".into());
        } else {
            instance.joined[slot] = true;
            instance.join_errors[slot] = error;
        }
    }

    async fn drain_children(&self, slot: usize, workers: &mut tokio::task::JoinSet<()>) {
        workers.abort_all();
        let mut drained = 0usize;
        let mut error = None;
        while let Some(result) = workers.join_next().await {
            drained = drained.saturating_add(1);
            if let Err(failure) = result {
                if !failure.is_cancelled() {
                    error = Some(format!("original pending child join: {failure}"));
                }
            }
        }
        let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(instance) = state.instances.get_mut(self.index) {
            instance.child_sets[slot] = Some(drained);
            instance.child_errors[slot] = error;
        }
    }
}

async fn c01_stop_original_worker_for_test(
    mut worker: tokio::task::JoinHandle<()>,
    owner: &C01UdpInstanceForTest,
    slot: usize,
) {
    let id = worker.id();
    // Exactly the original stop timeout and same handle; never poll Ready twice.
    let (result, forced_abort) = match timeout(Duration::from_secs(1), &mut worker).await {
        Ok(result) => (result, false),
        Err(_) => {
            worker.abort();
            (worker.await, true)
        }
    };
    let error = if forced_abort {
        Some("original one-second stop required abort; child drain is not proved".into())
    } else {
        result
            .err()
            .filter(|e| !e.is_cancelled())
            .map(|e| e.to_string())
    };
    owner.joined(slot, id, error);
}

#[allow(clippy::too_many_arguments)]
async fn c01_validation_until_joined_for_test(
    observations: DirectValidationIngress,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: String,
    worker_permits: Arc<tokio::sync::Semaphore>,
    shutdown_rx: watch::Receiver<bool>,
    owner: C01UdpInstanceForTest,
) {
    let mut workers = tokio::task::JoinSet::new();
    {
        let scheduler = run_direct_validation_scheduler_with_owned_workers(
            observations,
            udp.clone(),
            peers,
            transport,
            local_virtual_ip,
            worker_permits,
            &mut workers,
        );
        tokio::pin!(scheduler);
        tokio::select! {
            _ = &mut scheduler => {},
            _ = wait_for_udp_direct_shutdown(shutdown_rx) => {},
        }
    }
    udp.cancel_all_direct_validation_sessions().await;
    owner.drain_children(0, &mut workers).await;
}

#[allow(clippy::too_many_arguments)]
async fn c01_peer_reflexive_until_joined_for_test(
    ingress: PeerReflexiveIngress,
    control: ControlClient,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    worker_permits: Arc<tokio::sync::Semaphore>,
    shutdown_rx: watch::Receiver<bool>,
    owner: C01UdpInstanceForTest,
) {
    let mut workers = tokio::task::JoinSet::new();
    {
        let scheduler = run_peer_reflexive_signal_loop_with_owned_workers(
            ingress,
            control,
            udp,
            peers,
            punch_deduplicator,
            worker_permits,
            &mut workers,
        );
        tokio::pin!(scheduler);
        tokio::select! {
            _ = &mut scheduler => {},
            _ = wait_for_udp_direct_shutdown(shutdown_rx) => {},
        }
    }
    owner.drain_children(1, &mut workers).await;
}
