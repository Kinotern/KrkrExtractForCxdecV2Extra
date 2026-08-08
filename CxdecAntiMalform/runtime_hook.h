#pragma once
#include <windows.h>
#include <cstdint>

// Install a runtime hook on the engine's TJS bytecode loading function.
// The target is located via wildcard pattern search.
//
// When the engine loads a TJS script, the hook callback checks if it's
// "startup.tjs".  If so, it reads the decrypted TJS bytecode from the
// engine's stream object, patches it (System.checkSignature bypass), and
// writes a _crack.exe with all patches applied.

// Search the engine module for the hook target using the wildcard pattern
// and install a Detours hook. Returns true if hook was installed.
bool InstallRuntimeHook();

// Remove the hook. Called during plugin cleanup.
void RemoveRuntimeHook();
