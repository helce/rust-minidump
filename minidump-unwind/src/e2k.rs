use super::impl_prelude::*;
use minidump::format::CONTEXT_E2K;
use minidump::{CpuContext, MinidumpContext, MinidumpContextValidity, MinidumpRawContext};
use std::collections::HashSet;
use tracing::trace;

async fn get_caller_by_stacks<P>(
    ctx: &CONTEXT_E2K,
    args: &GetCallerFrameArgs<'_, P>,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    // pcsp_hi(ind) shows next empty word
    let pcsp_hi = ctx.get_register("pcsp_hi", args.valid())? - 0x20;
    // base - doesnot change
    let pcsp_lo = ctx.get_register("pcsp_lo", args.valid())?; 
    let pcsp_base = pcsp_lo & 0xffff_ffff_ffff;
    // to get cr-s, need to read previous quad word
    let cr0_lo = args
        .stack_memory
        .get_memory_at_address(pcsp_base + (pcsp_hi & 0xffff_ffff) - 0x20)?;
    let cr0_hi = args
        .stack_memory
        .get_memory_at_address(pcsp_base + (pcsp_hi & 0xffff_ffff) - 0x18)?;
    let cr1_lo = args
        .stack_memory
        .get_memory_at_address(pcsp_base + (pcsp_hi & 0xffff_ffff) - 0x10)?;
    let cr1_hi = args
        .stack_memory
        .get_memory_at_address(pcsp_base + (pcsp_hi & 0xffff_ffff) - 0x8)?;
    let caller_ctx = CONTEXT_E2K {
        pcsp_lo: pcsp_lo,
        pcsp_hi: pcsp_hi,
        cr0_lo: cr0_lo,
        cr0_hi: cr0_hi,
        cr1_lo: cr1_lo,
        cr1_hi: cr1_hi,
        ..CONTEXT_E2K::default()
    };

    let mut valid = HashSet::new();
    valid.insert("pcsp_lo");
    valid.insert("pcsp_hi");
    valid.insert("cr0_lo");
    valid.insert("cr0_hi");
    valid.insert("cr1_lo");
    valid.insert("cr1_hi");

    let context = MinidumpContext {
        raw: MinidumpRawContext::E2k(caller_ctx),
        valid: MinidumpContextValidity::Some(valid),
    };
    Some(StackFrame::from_context(context, FrameTrust::CF))
}

pub async fn get_caller_frame<P>(
    ctx: &CONTEXT_E2K,
    args: &GetCallerFrameArgs<'_, P>,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    // .await doesn't like closures, so don't use Option chaining
    let mut frame = None;
    if frame.is_none() {
        frame = get_caller_by_stacks(ctx, args).await;
    }
    let mut frame = frame?;

    // if the instruction is within the first ~page of memory, it's basically
    // null, and we can assume unwinding is complete.
    if frame.context.get_instruction_pointer() < 4096 {
        trace!("instruction pointer was nullish, assuming unwind complete");
        return None;
    }
    // Ok, the frame now seems well and truly valid, do final cleanup.
    Some(frame)
}
