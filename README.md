# `__stack_chk_fail` remover

`references[filename]` is a string obtained by the `XREF` to `__stack_chk_fail` from Ghidra.

Libraries are stored in `../WORKING/`.

The scripts removes the conditionnal jump (`b.ne`) which compare the stack canary by doing the comparaison a second time.

/!\ This opens large security holes

