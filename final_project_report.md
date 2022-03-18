# Ghidra Script for Automatic Use-After-Free Detection in Binary Code

## Fei Guo

## Introduction

In this project, I'll explore doing Ghidra scripting for automatic detection of pointers' user-after-free (UAF) in binary code. I'll present my Ghidra script for UAF detection, and show a few examples where it succeeds, and some cases that it doesn't, after which I'll propose some further improvements.

Before I worked on this script, I read through Alexei's MallocTrace script (which was written in Java), which turns out to be helpful, although the ideas are quite different. Basically, for MallocTrace, we need to look at all calls to `malloc` and trace back the parameter of `malloc`. For UAF detection, on the other hand, we can't start from `free` and trace backward, but instead, we need to start from `malloc` and trace forward. 

The script is at the end of the report.


## Complexities

This is our starting point:

`int *p; p = malloc(NUM_BYTES);`

We find each call like this and move forward to see how `p` is used. With this idea in mind, let's see how things can get tricky:

* name reuse: after malloc'ing for `p`, let's say we do a `free(p); p = malloc(MORE_BYTES);`. Apparently, `p` is "used" after free, but it's assigned to the return value of a new `
malloc`, so this variable has no relation with the previous one.

* aliasing: `p` is re-assigned to some other variable, say `q`, though `int *q = p;`, and then after `free(p);`, there is a `*q = 4;`. This is an obvious UAF, but aliasing makes it harder to tackle.

* pointer paased as a paramter: `p` is passed as a parameter to a function, e.g, `do_something(p);`.

* pointer as a return value: `p` is returned as a pointer to a caller, e.g, `return p;`.

* branches: the use of `p` depends on which branch the program takes, e.g, `if (flag) free(p); else *p = NUM;`.

* global pointer: `p` is declared as a global variable, and we can't glean its usages by only looking at `main` or some other function.

Each of these cases can get difficult to handle if we analyze it purely in assembly. 

## How Ghidra helps

Fortunately, Ghidra comes in handy for this task for several reasons:

* its decompiler automatically tries to generate C code that is in SSA (Single Static Assignment) form. This means that some cases are automatically handled by Ghidra, for example, the previous `name reuse` case, because Ghidra will give the variable for the second malloc a different name. What's even better, Ghidra can recognize the aliasing and determine the actual variable we are manipulating. We'll see an example shortly for this.

* its decompiler gives us the information about the parameters of a function, which disassembler doesn't give on its own. We need this capability of Ghidra to deal with the case that the pointer gets passed as a parameter to another function, and see how the function uses the pointer.

* its data-flow analysis gives us a good starting point for how a variable is defined and used. For example, after auto-analysis, we can first get a function's decompiled HighFunction, then use it to get a Varnode from some call site of `malloc`, and then get the descendants (further use) of the Varnode.

## The Algorithm

Here is the outline of the algorithm I implemented for detecting UAF in Ghidra:

1. Get a list of functions (`callers`) that called `malloc`
2. Loop through each caller, and collect all the `callsites` that issued the operation of calling `malloc`
3. For each callsite, get the newly `malloc`ed `pointer`  and initialize the bookkeeping free_flag as False, i.e, not freed
4. Get the descendants (i.e, further usages of a variable) of the `pointer` through Ghidra API
5. for each descendant of the `pointer`, we do a case analysis of its Opcode. 	
	* If it is used as a parameter in a function call, we check if the function name is `free`, if it is, mark the free_flag as True. Otherwise, we step into the function and look at how the pointer is used inside that function.
	* If it is used as a return value, we track down how the caller of the current function uses the pointer in its function body.
	* If it is used after it's already been freed, we deem this use as UAF and report it before terminating.
	* Otherwise we skip this usage and continue.

With this simple algorithm, let's look at some examples where it succeeds in detecting a UAF.

## Examples 

### 1. Aliasing handling

Here is a C program that `malloc` for two pointers and then free one, after which making one an alias of the other. 

```c
#include <stdlib.h>

void do_p(int *p) {
    p[0] = 1;
    p[1] = 2;
    p[2] = 3;
    return;
}
int main() {
    int *p = malloc(sizeof(int) * 4);
    int *q = malloc(4);
    free(q);
    q = p;
    do_p(q);
    free(p);
    q[3] = 4;
}

```
The script has no problem detecting this UAF, thanks to the auto de-aliasing of Ghidra's decompiler, which we can see in the decompiled C code:
```c
undefined8 entry(void)

{
  void *pvVar1;
  void *pvVar2;
  
  pvVar1 = __stubs::_malloc(0x10);
  pvVar2 = __stubs::_malloc(4);
  __stubs::_free(pvVar2);
  _do_p(pvVar1);
  __stubs::_free(pvVar1);
  *(undefined4 *)((long)pvVar1 + 0xc) = 4;
  return 0;
}
```
As we can see, although we used `q`, an alias of `p` in `do_p(q)` and `q[3]=4`, Ghidra tells us that it's still `pvVar1`, which simplified the detection a lot. And here is the running result of the detector:

```
UAF_detector.py> Running...
--------------------
Starting detecting for pointer assigned at 100003f2d
Pointer freed at 100003f68
UAT Detected at: 100003f73
Already Freed at: 100003f68
--------------------
Starting detecting for pointer assigned at 100003f3b
Pointer freed at 100003f4b
UAF_detector.py> Finished!
```

### 2. Freed in another function

Here is a C program that does `malloc` for two pointers, then frees one, after which makes an alias and frees the alias in another function `do_p`, then uses the pointer for assignment.

```c
#include <stdlib.h>

void do_p(int *p) {
    *p = 4;
    free(p);
}
int main() {
    int *p = malloc(sizeof(int) * 4);
    int *q = malloc(4);
    free(q);
    q = p;
    do_p(q);
    q[3] = 4;
    return 0;
}
```

As usual, Ghidra did de-aliasing for us, which makes the detector's job easier.

```c
undefined8 entry(void)
{
  void *pvVar1;
  void *pvVar2;
  
  pvVar1 = __stubs::_malloc(0x10);
  pvVar2 = __stubs::_malloc(4);
  __stubs::_free(pvVar2);
  _do_p(pvVar1);
  *(undefined4 *)((long)pvVar1 + 0xc) = 4;
  return 0;
}
```

The detector has no problem identifying that the actual `p` pointer has already been freed inside the function `do_p`, and reports its further usage as a violation.

```
UAF_detector.py> Running...
--------------------
Starting detecting for pointer assigned at 100003f34
Pointer freed at 100003f0d
UAT Detected at: 100003f6e
Already Freed at: 100003f0d
--------------------
Starting detecting for pointer assigned at 100003f42
Pointer freed at 100003f52
UAF_detector.py> Finished!
```

### 3. Pointer returned to another function after malloc

Here is a C program where a pointer is initialized (malloc'ed) inside a helper function, and then returned to the `main` function, which uses this pointer before freeing it and using it again.

```c
#include <stdlib.h>
#include <stdio.h>

int *get_ptr() {
	int *p;
	p = malloc(4);
	return p;
}

int main() {
	int *intp;
	intp = get_ptr();
	*intp = 4;	
	free(intp);
	*intp = 3;
	return 1;
}
```

The algorithm succeeds in detecting the UAF since it tracks down the use of the pointer in the caller of the `get_ptr` function. We can see from the output below that the pointer initialized at `100003f2d` was returned and assigned to another pointer at `100003f4f`, and the latter pointer was freed and re-used, causing a UAF.

```
UAF_detector.py> Running...
--------------------
Starting detecting for pointer assigned at 100003f2d
--------------------
Starting detecting for pointer assigned at 100003f4f
Pointer freed at 100003f69
UAT Detected at: 100003f72
Already Freed at: 100003f69
UAF_detector.py> Finished!
``` 

### 4. A failed case when encountering branches

Here is a C program that will either free a pointer or deference it based on an error condition. However, since the detector is not context-sensitive, it fails to notice that only when `abrt` is not 0 that the pointer will be dereferenced, but the `free` operation only happens when abrt is 0, which contradicts the previous condition, making the deref a non-violation.

```c
#include <stdlib.h>

int err(){
    int var = 7 * 3 - 1;
    return ++var;
}

int main() {
    int ret, abrt;
    abrt = 1;
    int* ptr = (int*)malloc (4);
    if (err() > 0) {
        abrt = 0;
        free(ptr);
    }
    if (abrt) {
        ret = *ptr;
    }
    return ret;
}
```

See the false alarm:

```
UAF_detector.py> Running...
--------------------
Starting detecting for pointer assigned at 100003f3b
Pointer freed at 100003f60
UAT Detected at: 100003f73
Already Freed at: 100003f60
UAF_detector.py> Finished!
```

One thing interesting to note is that while the decompiled function puts the `free` branch after the dereferencing branch, the detector nonetheless reports a UAF. The reason is the `descendants` of a varnode are actually ordered by their positions in the assembly listing, not the decompiled code. The `free` operation comes before the deref operation in the listing, thus leading the detector to see a use after `free`.

```c
undefined4 entry(void)
{
  int iVar1;
  undefined4 *puVar2;
  undefined4 local_10;
  
  puVar2 = (undefined4 *)__stubs::_malloc(4);
  iVar1 = _err();
  if (iVar1 < 1) {
    local_10 = *puVar2;
  }
  else {
    __stubs::_free(puVar2);
  }
  return local_10;
}
```

## Limitation and future improvements:

Frankly, the previous algorithm is very naive, and in particular, does not handle these cases:

* spurious use after free: for example, after the pointer was freed, usages like this `p = !p; p++; p--;` should not be counted as UAF. But since this kind of use is rare in real-world programming, and can be considered bad style, we nonetheless say they are violations and report UAF.

* branches: it will give a false alarm when it sees something like `if (flag) free(p); else *p = NUM;` , which it will say `*p = NUM` is a UAF, but it is not. I tried to handle this case by forking a new "detector" and letting each detector go down one branch, but I don't know how to follow a branch in Ghidra's pcode. What I tried was, every time I see a BRANCH pcode, I get the address of its first input, and try to get the PcodeOps from the address, but can't get any results (i.e, it returns an empty set). So I ended up not handling branches.
```
    if (op.getOpcode() == PcodeOp.BRANCH):
        addr = op.getInput(0).getAddress()        
        print "target instructions:", list(highfunc.getPcodeOps(addr))
``` 

* global variables: because I could not decide which usage happens first if these usages are in different functions that have no apparent order of happening, the detector doesn't handle global pointers. 


To sum up, the detector is far from context-sensitive. It doesn't handle branches, loops, or pointers defined as global variables. To make the detector work in such scenarios, we may need to do loop unrolling, and employ an SMT solver to identify which branches are feasible during execution. This is currently beyond the scope of this project, and I hope to learn more about this in the upcoming Compiler course. 


## The Script

```python
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
    For each of the callsites, first, we get its output (i.e, the varnode that
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

```