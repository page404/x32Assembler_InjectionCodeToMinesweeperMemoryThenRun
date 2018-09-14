rc winHello.rc
ml /c /coff winHello.asm
link /subsystem:windows winHello.obj winHello.res
pause