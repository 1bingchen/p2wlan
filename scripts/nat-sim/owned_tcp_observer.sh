#!/usr/bin/env bash
# Optional diagnostics for exactly the first original status pair per round.
# PIDS remains the only live-owner collection. These PID variables identify
# the pipe protocol peers; only the existing owner API authorizes waits/kills.

_tcp_close_fds() { exec 6>&- 7>&- 8>&- 9>&-; }

owned_tcp_select_pair() {
  if [[ "${_TCP_PAIR_ROUND:-}" != "$ROUND_DIR" ]]; then
    _TCP_PAIR_ROUND=$ROUND_DIR; _TCP_PAIR_SELECTED=0
    _TCP_CONTEXT_DIR=""; _TCP_A_OBSERVER_PID=""; _TCP_B_OBSERVER_PID=""
  fi
  [[ "${NAT_SIM_TCP_OBSERVER:-0}" == 1 && "$_TCP_PAIR_SELECTED" == 0 ]] || return 0
  _TCP_PAIR_SELECTED=1
  local a_pid="$1" b_pid="$2" a_port="$3" b_port="$4" cutoff image stage_cutoff
  # Reserve two observer and two original status-child receipt slots before
  # any spawn. No capacity fallback can create an unregistered observer.
  if ! _round_owned "$a_pid" || ! _round_owned "$b_pid" || (( ${#_ROUND_OWNER_PID[@]} + 4 > 128 )); then
    printf '%s\n' owner_or_capacity_unavailable >"$ROUND_DIR/tcp-observer-unavailable"
    return 0
  fi
  if ( : <&6 ) 2>/dev/null || ( : <&7 ) 2>/dev/null || ( : <&8 ) 2>/dev/null || ( : <&9 ) 2>/dev/null; then
    printf '%s\n' reserved_fd_in_use >"$ROUND_DIR/tcp-observer-unavailable"
    return 0
  fi
  cutoff=$(_round_project_deadline_ms "$WORK_DEADLINE") || return 0
  if [[ "${OVERLAY_DEADLINE:-0}" -gt 0 ]]; then
    stage_cutoff=$(_round_project_deadline_ms "$OVERLAY_DEADLINE") || return 0
    if (( stage_cutoff < cutoff )); then cutoff=$stage_cutoff; fi
  fi
  if ! image=$(python3 "$ROOT_DIR/scripts/nat-sim/owned_tcp_manifest.py" pair \
      --base "$BASE_DIR" --round-dir "$ROUND_DIR" --owner "$$" --cutoff-ms "$cutoff" \
      --a-pid "$a_pid" --b-pid "$b_pid" --a-port "$a_port" --b-port "$b_port"); then
    printf '%s\n' original_binding_or_setup_unavailable >"$ROUND_DIR/tcp-observer-unavailable"
    return 0
  fi
  local directory="$ROUND_DIR/tcp-observation"
  if ! { exec 8<>"$directory/a-in" 9<>"$directory/a-out" 6<>"$directory/b-in" 7<>"$directory/b-out"; }; then
    _tcp_close_fds
    printf '%s\n' fifo_open_unavailable >"$ROUND_DIR/tcp-observer-unavailable"
    return 0
  fi
  # Open the native read/write endpoints independently. Sharing >&9 with the
  # Python reader would also share O_NONBLOCK with the C writer's OFD.
  "$image" <"$directory/a-in" >"$directory/a-out" 6>&- 7>&- 8>&- 9>&- &
  _TCP_A_OBSERVER_PID=$!
  round_register_process tcp-server-observer-a "$_TCP_A_OBSERVER_PID"
  "$image" <"$directory/b-in" >"$directory/b-out" 6>&- 7>&- 8>&- 9>&- &
  _TCP_B_OBSERVER_PID=$!
  round_register_process tcp-server-observer-b "$_TCP_B_OBSERVER_PID"
  _TCP_CONTEXT_DIR=$directory
  _TCP_JOIN_CUTOFF_MS=$cutoff
}

_tcp_join_owned() {
  local pid="$1" end="$2" now started index status term_sent=0 killed=0
  started=$(_round_now)
  while _round_owned "$pid"; do
    if _round_wait_finished "$pid"; then break; fi
    # A completed job may retain a cached status after its numeric PID has
    # been reused. Only the actual Bash job table authorizes a signal.
    if ! _round_job_live "$pid"; then
      if wait "$pid"; then status=0; else status=$?; fi
      round_record_wait "$pid" "$status"
      break
    fi
    now=$(_round_now)
    if (( now >= end )); then
      printf '%s\n' join_pending_at_fixed_cutoff >"$ROUND_DIR/tcp-observer-unavailable"
      break
    fi
    if (( now - started >= 200 && term_sent == 0 )); then
      if _round_job_live "$pid"; then kill -TERM "$pid" 2>/dev/null || true; fi
      term_sent=1
    fi
    if (( now - started >= 300 && killed == 0 )); then
      if _round_job_live "$pid"; then kill -KILL "$pid" 2>/dev/null || true; fi
      killed=1
      CLEANUP_FORCED=1
      for ((index=0; index < ${#_ROUND_OWNER_PID[@]}; index++)); do
        if [[ "${_ROUND_OWNER_PID[$index]}" == "$pid" ]]; then _ROUND_OWNER_FORCED[$index]=1; break; fi
      done
    fi
    sleep 0.01
  done
}

owned_tcp_join_pair() {
  [[ -n "${_TCP_CONTEXT_DIR:-}" ]] || return 0
  # Both actual status children have joined. Closing/writing the private
  # command endpoints requests normal native exit, never a numeric PID kill.
  printf 'quit\n' >&8 || true
  printf 'quit\n' >&6 || true
  local pid end
  end=$(($(_round_now) + 1000))
  if (( _TCP_JOIN_CUTOFF_MS < end )); then end=$_TCP_JOIN_CUTOFF_MS; fi
  for pid in "$_TCP_A_OBSERVER_PID" "$_TCP_B_OBSERVER_PID"; do
    # One shared join cap only shrinks the original fixed work cutoff. Never
    # start/rebase the round finalizer's resource grace just for diagnostics.
    _tcp_join_owned "$pid" "$end"
  done
  _tcp_close_fds
  _TCP_CONTEXT_DIR=""
}
