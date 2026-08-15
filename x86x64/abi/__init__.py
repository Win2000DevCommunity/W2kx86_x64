"""ABI translation: TEB segment remapping and calling-convention conversion."""

from .callconv import (
    FIRST_STACK_ARG_CALLEE,
    FIRST_STACK_ARG_CALLER,
    RBP_HOME_BASE,
    X86_FIRST_ARG_DISP,
    ArgLocation,
    CallConv,
    arg_location,
    arg_locations,
    arg_slot_to_rbp_home,
    is_aligned,
    ret_pop_to_arg_count,
    stack_bytes_for_args,
    x86_arg_index,
    x86_disp_to_rbp_home,
    x86_disp_to_rbp_local,
)
from .teb import (
    FS_TO_GS,
    POINTER_GS_OFFSETS,
    TEB_FIELDS,
    TebField,
    access_width,
    field_at_fs,
    field_at_gs,
    field_by_name,
    fs_to_gs,
    is_known_fs_offset,
    operand_size,
)

__all__ = [
    'FIRST_STACK_ARG_CALLEE', 'FIRST_STACK_ARG_CALLER', 'FS_TO_GS',
    'POINTER_GS_OFFSETS', 'RBP_HOME_BASE', 'TEB_FIELDS', 'TebField',
    'X86_FIRST_ARG_DISP', 'ArgLocation', 'CallConv', 'access_width',
    'arg_location', 'arg_locations', 'arg_slot_to_rbp_home', 'field_at_fs',
    'field_at_gs', 'field_by_name', 'fs_to_gs', 'is_aligned',
    'is_known_fs_offset', 'operand_size', 'ret_pop_to_arg_count',
    'stack_bytes_for_args', 'x86_arg_index', 'x86_disp_to_rbp_home',
    'x86_disp_to_rbp_local',
]
