# RDR2 Native Function Finder

This tool helps identify RDR2 native functions in the Red Dead Redemption 2 executable using IDA Pro.

[Discord](https://discord.gg/S4pRcx5Sua)

## Project Structure

The project has been organized into separate modules for better maintainability:

- `NV-Utils.py`: Core functionality for working with native functions.
- `NV-UI.py`: PyQt-based user interface for a more interactive experience. - Vibe coded with Claude 3.7/4 :)

### Features

- **Scan Natives**: Scan the executable for native functions
- **Lookup Native**: Look up a native function by its hash
- **Find RegisterNative**: Locate the `RegisterNative` function in the binary
- **Sideload Natives**: Load native function definitions from an external file (i.e. `rdr3natives.json`)

## Dependencies

- IDA Pro with Python support
- ida_domain module
- PyQt5

## Planned

- **GTAV Support**: Extend support to Grand Theft Auto V

## Credits

- rdr3natives.json: [VORPCORE](https://github.com/VORPCORE/RDR3natives)
