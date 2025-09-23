from typing import Any
import idaapi
import struct
from ida_domain import Database

OFFSET_TO_HASH = 0x8
OFFSET_TO_LEA = 0x11


db = Database()


def get_all_natives_from_ida(register_native_name: str) -> list[tuple[int, int, str]] | None:

    registerNativeFunc = db.functions.get_function_by_name(
        register_native_name)

    if not registerNativeFunc:
        print("Error: Cannot find RegisterNative function in database")
        return

    calls = db.functions.get_callers(registerNativeFunc)
    print(f"{len(calls)} Namespaces call RegisterNative")

    xrefsGen = db.xrefs.calls_to_ea(registerNativeFunc.start_ea)

    count = 0
    count_valid = 0
    count_null = 0
    natives = []

    for xref in xrefsGen:
        count += 1
        hash_offset = xref - OFFSET_TO_HASH

        hash_bytes = db.bytes.get_bytes_at(hash_offset, 8)

        if not hash_bytes or len(hash_bytes) < 8:
            print(f"Error: Cannot read bytes at {hex(hash_offset)}")
            continue

        hash = int.from_bytes(hash_bytes, byteorder='little')
        native_func_ea = _get_func_ea_from_xref(xref)

        if not hash_bytes or not native_func_ea:
            print(f"Error: Cannot read bytes at {hex(xref)}")
            continue

        try:
            native_func = db.functions.get_at(native_func_ea)
        except Exception as e:
            print(
                f"An error occurred while getting function at {hex(native_func_ea)}: {e}")
            continue

        if not native_func:
            print(
                f"Error: No function found at {hex(native_func_ea)} for hash {hex(xref)}")
            continue

        native_func_name = db.functions.get_name(native_func)

        natives.append(
            (hash, native_func_ea, native_func_name))

        if native_func_name.startswith("nullsub_"):
            count_null += 1
        else:
            count_valid += 1

    print("Total/Valid/Null Natives Found:")
    print(f"{count}/{count_valid}/{count_null}")

    return natives


def _get_func_ea_from_xref(xref) -> int | None:
    lea_address = xref - OFFSET_TO_LEA

    try:
        displacement_bytes = db.bytes.get_bytes_at(lea_address + 3, 4)

        if not displacement_bytes:
            print(f"Error: Could not read bytes at {hex(lea_address + 3)}")
        else:
            # Unpack as a 32-bit signed little-endian integer
            displacement = struct.unpack('<i', displacement_bytes)[0]
            rip_val = lea_address + 7
            target_address = rip_val + displacement
            return target_address

    except Exception as e:
        print(f"An error occurred: {e}")


def SigSearch(Signature: str) -> int | list[int] | None:
    if not Signature:
        print("Error: No signature provided")
        return

    end_ea = idaapi.inf_get_max_ea()
    ea = idaapi.inf_get_min_ea()

    pattern = idaapi.compiled_binpat_vec_t()

    idaapi.parse_binpat_str(
        pattern,
        idaapi.inf_get_start_ea(),
        Signature,
        16,
        0
    )

    pat_len = sum(len(pat.bytes) for pat in pattern)

    matches = []
    while True:
        ea, _ = idaapi.bin_search(
            ea,
            end_ea,
            pattern,
            idaapi.BIN_SEARCH_CASE
        )

        if ea == idaapi.BADADDR:
            break

        matches.append(ea)
        ea += pat_len

    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        return matches


def FindRegisterNative(Signature: str | None = None) -> int | list[int] | None:
    SIGNATURE = "4C 8B 05 ? ? ? ? 4C 8B C9 49 F7 D1"
    Signature = Signature or SIGNATURE

    data = SigSearch(Signature)

    if not data:
        print("Error: No matches found for RegisterNative")
        return

    if isinstance(data, int):
        print(f"Found RegisterNative at: {hex(data)}")
        return data

    print(f"Found {len(data)} matches for RegisterNative:")
    for ea in data:
        print(f"- {hex(ea)}")
    return data


def retrieveStringFromMemory(address) -> Any | None:
    try:

        try:
            displacement_bytes = idaapi.get_bytes(address + 3, 4)
            if not displacement_bytes:
                print(
                    f"- {hex(address)}: Could not read displacement bytes")
                return None
        except Exception as e:
            print(f"- {hex(address)}: Error reading memory - {e}")
            return None

        displacement = struct.unpack('<i', displacement_bytes)[0]
        target_address = address + 7 + displacement

        build_str = idaapi.get_strlit_contents(
            target_address, -1, idaapi.STRTYPE_C)

        return build_str

    except Exception as e:
        print(f"- {hex(address)}: Error - {str(e)}")

    return None


def FindGameBuild(xRefSignature: str | None = None) -> int | list[int] | None:
    SIGNATURE = "48 8D 05 ? ? ? ? C3 48 8D 05 ? ? ? ? C3 48 8B 81 ? ? ? ? 48 85 C0 74 ? 48 8B 40 ? 48 85 C0"
    xRefSignature = xRefSignature or SIGNATURE

    data = SigSearch(xRefSignature)
    if not data:
        print("Error: No matches found for Game Build")
        return None

    if isinstance(data, int):
        address = data
        return retrieveStringFromMemory(address)

    elif isinstance(data, list):
        print(f"Found {len(data)} potential game build functions:")
        results = []

        for address in data:
            build_str = retrieveStringFromMemory(address)

            if build_str:
                build_str = build_str.decode('utf-8')
                print(f"- {hex(address)}: {build_str}")
                results.append(build_str)
            else:
                print(f"- {hex(address)}: Could not read string")

        if results:
            # Return the first valid result
            return results[0]
        return None


# Console mode entry point
if __name__ == "__main__":
    idaapi.msg_clear()
    # FindRegisterNative()
    print(FindGameBuild())
    # get_all_natives_from_db('RegisterNative')
    pass
