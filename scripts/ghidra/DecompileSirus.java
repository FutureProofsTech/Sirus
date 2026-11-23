// Ghidra headless post-script focused on the injected .sirus segment and the
// patched host functions, so host std noise is not confused with VM evidence.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryBlock;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileSirus extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = args.length > 0 ? args[0] : "sirus-decompiled.txt";
        MemoryBlock block = currentProgram.getMemory().getBlock(".sirus");
        PrintWriter writer = new PrintWriter(new FileWriter(outputPath));
        DecompInterface decompiler = new DecompInterface();
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        FunctionManager manager = currentProgram.getFunctionManager();

        if (block == null) {
            writer.println("/* .sirus section missing */");
            writer.close();
            println("NO .sirus SECTION");
            return;
        }
        writer.println("BLOCK .sirus start=" + block.getStart() + " end=" + block.getEnd()
                + " exec=" + block.isExecute() + " write=" + block.isWrite()
                + " initialized=" + block.isInitialized());
        int considered = 0;
        int completed = 0;
        int failed = 0;
        int inSegment = 0;
        for (Function function : manager.getFunctions(true)) {
            Address entry = function.getEntryPoint();
            boolean inside = block.contains(entry);
            boolean hostTarget = function.getName().contains("sirus_demo")
                    || function.getName().contains("sirus_marker_target")
                    || function.getName().contains("sirus_static_target");
            if (!inside && !hostTarget) {
                continue;
            }
            considered++;
            if (inside) {
                inSegment++;
            }
            writer.println("==== " + (inside ? "SIRUS_VM" : "HOST_TARGET") + " "
                    + function.getName() + " @ " + entry + " ====");
            try {
                DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
                if (result.decompileCompleted()) {
                    completed++;
                    writer.println(result.getDecompiledFunction().getC());
                } else {
                    failed++;
                    writer.println("/* INCOMPLETE: " + result.getErrorMessage() + " */");
                }
            } catch (Exception error) {
                failed++;
                writer.println("/* ERROR: " + error + " */");
            }
        }
        writer.println("/* considered=" + considered + " in_sirus=" + inSegment
                + " completed=" + completed + " failed=" + failed + " */");
        writer.close();
        println("WROTE " + outputPath + " considered=" + considered + " in_sirus=" + inSegment);
    }
}
