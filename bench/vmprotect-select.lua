-- VMProtect 3.11 demo selector for the Sirus comparison benchmark.
-- Run: vmprotect_con native protected -sf vmprotect-select.lua
function OnBeforeCompilation()
    local file = vmprotect.core():outputArchitecture()
    local map = file:mapFunctions()
    for i = 1, map:count() do
        local fn = map:item(i)
        if string.find(fn:name(), "sirus_demo_check", 1, true) then
            file:functions():addByAddress(fn:address(), CompilationType.Virtualization)
        end
    end
end
