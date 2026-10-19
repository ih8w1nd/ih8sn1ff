// Decompile functions at explicit image-relative addresses.
// Args: one or more hex RVAs (e.g. 0x165103c). Output goes to stdout with
// "=== RVA ..." headers so callers can split the sections.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileTargets extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (String arg : getScriptArgs()) {
                long rva;
                try {
                    rva = Long.decode(arg);
                } catch (NumberFormatException exc) {
                    println("=== BAD RVA: " + arg);
                    continue;
                }
                Address addr = currentProgram.getImageBase().add(rva);
                Function function = getFunctionContaining(addr);
                if (function == null) {
                    function = getFunctionAt(addr);
                }
                println("=== RVA " + arg + " -> " + addr);
                if (function == null) {
                    println("(no function at this address)");
                    continue;
                }
                println("function: " + function.getName() + " @ " + function.getEntryPoint());
                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (results != null && results.decompileCompleted()
                        && results.getDecompiledFunction() != null) {
                    println(results.getDecompiledFunction().getC());
                } else {
                    println("(decompile failed)");
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
