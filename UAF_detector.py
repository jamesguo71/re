from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from ghidra.program.model.pcode import PcodeOp


def setUpDecompiler():
    """
    Set up the decomp interface.
    :return: a set-up DecompInterface instance
    """
    decompInterface = DecompInterface()
    options = DecompileOptions()
    decompInterface.setOptions(options)
    decompInterface.toggleCCode(True)
    decompInterface.toggleSyntaxTree(True)
    decompInterface.setSimplificationStyle("decompile")
    if not decompInterface.openProgram(currentProgram):
        raise Exception("Decompiler can't open program")
    return decompInterface


def myGetCallers(funclist):
    """
    Given a list of functions `funclist`, find all the functions which call
    one of the function in `funclist`.
    :param funclist: [String] a list of function names
    :return: [Function] a list of Ghidra functions
    """
    functions = currentProgram.getFunctionManager().getFunctions(True)
    callers = set()
    for f in functions:
        if f.getName() in funclist:
            refs = getReferencesTo(f.getEntryPoint())
            for r in refs:
                caller = getFunctionContaining(r.getFromAddress())
                if caller and not caller.isThunk():
                    callers.add(caller)
    return callers


def myDecompileFunc(f):
    """
    Decompile a function and return its corresponding high function.
    :param f: a Ghidra function
    :return: a Ghidra High Function
    """
    dRes = decompInterface.decompileFunction(
        f, decompInterface.getOptions().getDefaultTimeout(),
        getMonitor())
    return dRes.getHighFunction()


def myFindCallSites(callers, funcs):
    """
    In each of the `callers`, find all the callsites that called one of the
     functions in `funcs`.
    :param callers: [Function] a list of Ghidra functions
    :param funcs: [String] a list of function names
    :return: [PcodeOpAST] a list of Ghidra PcodeOpAST, each representing its callsite Pcode
    """
    pcodeOps = []
    for caller in callers:
        highfunc = myDecompileFunc(caller)
        PcodeOps = highfunc.getPcodeOps()
        for op in PcodeOps:
            if op.getOpcode() == PcodeOp.CALL:
                calledVarnode = op.getInput(0)
                calledFunc = getFunctionAt(calledVarnode.getAddress()).getName()
                if calledFunc in funcs:
                    pcodeOps.append(op)
    return pcodeOps


class FreeInfo:
    """
    This datatype is just used to store the info about whether a pointer is freed,
    and if it's freed, where it was freed
    """
    def __init__(self, flag, position):
        self.flag = flag
        self.pos = position


def myCallSiteAnalyze(callsites):
    """
    For each of the callsites, first we get its output (i.e, the varnode that
    stores the return value of the function call). Then we initialize a FreeInfo
    object, mark its flag False (not freed), and then analyze its later usage by
    walking through its descendants.
    :param callsites: [PcodeOpAST], a list of call sites
    :return: Void
    """
    for p_op in callsites:
        # print "Call Site:", p_op
        ptr = p_op.getOutput()
        # print "Pointer:", ptr
        free_info = FreeInfo(False, -1)
        print "-" * 20
        print "Starting detecting for pointer assigned at", ptr.getPCAddress()
        myAnalyzeDescendants(ptr, free_info)



def myAnalyzeDescendants(ptr, free_info):
    """
    This function will analyze all the descendants (usage) of the `ptr`, and
    based on how it's used, take different actions.
    :param ptr: Varnode, the pointer we want to analyze
    :param free_info: the data object storing the status of the `ptr`
    :return: Void
    """
    descendants = list(ptr.getDescendants())
    # print "descendants", descendants
    for desc in descendants:
        # print "DESC:", desc.getMnemonic(), ":", desc

        # If it's used in any fashion after freeing, we deem it a UAF
        if free_info.flag:
            print "UAT Detected at:", desc.getSeqnum().getTarget()
            print "Already Freed at:", free_info.pos
            break
        if desc.getOpcode() == PcodeOp.CALL:
            addr = desc.getInput(0).getAddress()
            called_f = getFunctionAt(addr)
            called_fname = called_f.getName()
            # If it's used in a free call, mark it as invalid
            if called_fname in free_funcs:
                if free_info.flag:
                    print "Double Free of Pointer!"
                else:
                    free_info.flag = True
                    free_info.pos = desc.getSeqnum().getTarget()
                print "Pointer freed at", free_info.pos
            else:
                # in CALL, but not for the `free` function
                # step into the function and see how it's used as a param
                paramIdx = -1
                for _tempParamIdx, d in enumerate(desc.getInputs()):
                    if d == ptr:
                        # The 1st param to CALL pcode is addr, so we offset 1 here
                        paramIdx = _tempParamIdx - 1
                        break
                if paramIdx == -1:  # Not found
                    raise Exception("Didn't find the param")
                high_func = myDecompileFunc(called_f)
                num_param = high_func.getLocalSymbolMap().getNumParams()
                if num_param < paramIdx + 1:
                    print "Decompiled function doesn't use this param, skip"
                    continue
                param = high_func.getLocalSymbolMap().getParam(paramIdx)
                myAnalyzeDescendants(param.getRepresentative(), free_info)
        # The pointer returned by malloc is passed as the return value
        # So we check all the callers and see how it's used
        # Another case is the pointer is in a MULTIEQUAL, which usually means the program
        # branched before returning
        elif desc.getOpcode() == PcodeOp.RETURN or desc.getOpcode() == PcodeOp.MULTIEQUAL:
            caller_name = getFunctionContaining(ptr.getPCAddress()).getName()
            caller_list = [caller_name]
            calling_funcs = myGetCallers(caller_list)
            callsites = myFindCallSites(calling_funcs, caller_list)
            myCallSiteAnalyze(callsites)
        # This is used to handle the case that the returned pointer actually got cast or copied
        # first before making further use. We get the output from the case and take it as a pointer
        elif desc.getOpcode() == PcodeOp.CAST or desc.getOpcode() == PcodeOp.COPY:
            new_ptr = desc.getOutput()
            myAnalyzeDescendants(new_ptr, free_info)
        else:
            pass
            # print "Unimplemented"


def main():
    # Find all callers of malloc
    callers = myGetCallers(malloc_funcs)
    # Find the PcodeOpASTs of all callsites to malloc
    callsites = myFindCallSites(callers, malloc_funcs)
    # for each call, get its output, and walk through its descendants
    myCallSiteAnalyze(callsites)


if __name__ == "__main__":
    # For IDE hinting, ignore if user has no ghidra plugin installed
    try:
        from ghidra.ghidra_builtins import *
    except:
        pass
    decompInterface = setUpDecompiler()
    malloc_funcs = ["malloc", "_malloc"]
    free_funcs = ["free", "_free"]
    main()
