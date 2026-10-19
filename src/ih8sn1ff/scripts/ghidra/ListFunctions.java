// Print analyzed functions as "<entry>\t<name>", bounded by the first arg.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

public class ListFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        int limit = 20000;
        String[] args = getScriptArgs();
        if (args.length > 0) {
            try {
                limit = Integer.parseInt(args[0]);
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        FunctionManager manager = currentProgram.getFunctionManager();
        FunctionIterator iterator = manager.getFunctions(true);
        int count = 0;
        while (iterator.hasNext() && count < limit) {
            Function function = iterator.next();
            println(function.getEntryPoint() + "\t" + function.getName());
            count++;
        }
        println("TOTAL " + count);
    }
}
