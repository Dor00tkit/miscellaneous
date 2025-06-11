# **IDA RVA Jump Plugin**

Plugin for IDA Pro that lets you jump to a given RVA (Relative Virtual Address).

## Usage

Use the shortcut **Shift + G** to jump to an RVA,  
or select from the menu: `Edit -> Plugins -> Jump to RVA`.  
Enter the RVA (hex or decimal), and the view will move to the corresponding address.

## Installation

Copy `rva_jump.py` to:

- `%APPDATA%\Hex-Rays\IDA Pro\plugins\` (any user)  
- Or `C:\Program Files\IDA Pro\plugins\` (requires admin)

Restart IDA Pro.

## Compatibility

Tested on Windows with IDA Pro 8.4 and 9.0 only.
