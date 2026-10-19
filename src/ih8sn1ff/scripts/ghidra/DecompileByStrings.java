// Find defined strings containing any keyword, follow references to them,
// and decompile the containing functions (deduplicated, bounded).
// Args: keyword1 keyword2 ... [limit]  (last numeric arg = function cap, default 40)
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class DecompileByStrings extends GhidraScript {
    @Override
    public void run() throws Exception {
        List<String> keywords = new ArrayList<>();
        int limit = 40;
        for (String arg : getScriptArgs()) {
            try {
                limit = Integer.parseInt(arg);
            } catch (NumberFormatException exc) {
                keywords.add(arg);
            }
        }
        if (keywords.isEmpty()) {
            println("=== no keywords provided");
            return;
        }

        Set<Function> functions = new LinkedHashSet<>();
        DataIterator iterator = currentProgram.getListing().getDefinedData(true);
        while (iterator.hasNext() && functions.size() < limit && !monitor.isCancelled()) {
            Data data = iterator.next();
            if (data == null || data.getValue() == null) {
                continue;
            }
            String value = data.getValue().toString();
            boolean matched = false;
            for (String keyword : keywords) {
                if (value.contains(keyword)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                continue;
            }
            for (Reference ref : getReferencesTo(data.getAddress())) {
                Function function = getFunctionContaining(ref.getFromAddress());
                if (function != null) {
                    functions.add(function);
                }
                if (functions.size() >= limit) {
                    break;
                }
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            println("=== matched functions: " + functions.size());
            for (Function function : functions) {
                if (monitor.isCancelled()) {
                    break;
                }
                println("=== FUNCTION " + function.getName() + " @ " + function.getEntryPoint());
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
