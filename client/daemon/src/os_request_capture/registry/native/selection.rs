//! Pure original-order selection. Indices and phases grant no native IO fact.
use super::*;

pub(super) struct Selection {
    pub(super) selected: Vec<usize>,
    pub(super) skipped: Vec<usize>,
}

pub(super) fn select<'a>(
    plan: &RegisteredFlowPlan,
    slot: usize,
    packets: impl Iterator<
        Item = (
            usize,
            &'a [full::ReadFrameSpan],
            PhysicalPublicationState,
            bool,
        ),
    >,
) -> Check<Option<Selection>> {
    let mut coverage = full::FrameSpanCoverage::new(plan, slot).ok_or(unknown())?;
    let mut selected = Vec::new();
    let mut skipped = Vec::new();
    for (count, (index, spans, phase, retained)) in packets.enumerate() {
        if count >= full::MAX_FULL_PACKETS {
            return Err(unknown());
        }
        if phase == PhysicalPublicationState::DefinitelyNotHanded {
            let mut prospective = coverage.clone();
            let mut contributes = false;
            for span in spans {
                contributes |= prospective.add(span).map_err(|_| unknown())?;
            }
            if contributes {
                skipped.try_reserve(1).map_err(|_| unknown())?;
                skipped.push(index);
            }
            continue;
        }
        let mut contributes = false;
        for span in spans {
            contributes |= coverage.add(span).map_err(|_| unknown())?;
        }
        if !contributes {
            continue;
        }
        match phase {
            PhysicalPublicationState::Idle
            | PhysicalPublicationState::Open
            | PhysicalPublicationState::Publishing => return Ok(None),
            PhysicalPublicationState::Recorded if retained => {}
            PhysicalPublicationState::Recorded => return Ok(None),
            _ => return Err(unknown()),
        }
        selected.try_reserve(1).map_err(|_| unknown())?;
        selected.push(index);
        if coverage.is_complete() {
            return Ok(Some(Selection { selected, skipped }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
