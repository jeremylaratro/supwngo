/*
 * supwngo_ext.c -- the LEGITIMATE extension module for benchmark/corpus_libhijack/.
 *
 * HELD IDENTICAL ACROSS THE WHOLE FAMILY. One source, compiled once by
 * install_plugins.sh into a shared object with SONAME `libsupwngoext.so.1`, and
 * then installed into each target's documented plugin location. Every target in
 * the family loads THIS object in its legitimate configuration and calls the
 * family's documented init symbol `supwngo_plugin_init` on it, which is what
 * makes "the plugin feature works normally" a fact rather than a claim.
 *
 * The ONE thing that varies across the family is HOW THE DYNAMIC LOADER IS
 * POINTED AT AN EXTENSION MODULE -- cwd-relative dlopen, an environment-named
 * directory, a bare soname handed to the loader's own search, a writable
 * RUNPATH/RPATH entry, or a directory scan. The module itself, its symbol, and
 * the program's use of it are constants. The attacker's job is never to defeat
 * this file; it is to get a DIFFERENT file loaded in its place.
 *
 * Deliberately boring: it prints nothing of its own, has no constructor, and
 * returns a fixed description string. An attacker-supplied replacement is
 * distinguishable from this one by behaviour alone (it spawns a shell), so the
 * legitimate module must not do anything that could be mistaken for that.
 */

/* The family's documented plugin ABI: one exported function taking no
 * arguments and returning a human-readable description of the extension.
 * The host program calls it immediately after loading and prints the result. */
const char *supwngo_plugin_init(void)
{
    return "supwngo reference extension v1 (legitimate, no side effects)";
}
