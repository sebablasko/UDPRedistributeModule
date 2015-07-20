# UDPRedistributeModule
Modulo del para el kernel que usa el framework de los netfilters.

Intercepta los paquetes en la etapa más temprana de distribucción en el sistema (PREROUTING).

Si el paquete es del tipo (17, UDP) y dirigido al puerto especificado en la instalación del modulo, se redistribuye a alguno de los puertos especificados en la instalación.

Instalación
------------

`make`
`sudo insmod UDPRedistributeModule.ko verbose={0,1,2} _target_hook_port_={PUERTO_A_INTERCEPTAR} _redirect_ports_={PUERTOS_A_REDIRECCIONAR}`

EJ.
`sudo insmod UDPRedistributeModule.ko verbose=2 _target_hook_port_=13131 _redirect_ports_=9898,9899,9900,1111`