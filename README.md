# UDPRedistributeModule
Modulo del para el kernel que usa el framework de los netfilters.

Intercepta los paquetes en la etapa más temprana de distribucción en el sistema (PREROUTING).

Si el paquete es del tipo (17, UDP) y dirigido al puerto especificado en la instalación del modulo, se redistribuye a alguno de los puertos especificados en la instalación.

Instalación
------------

`make`

`sudo insmod UDPRedistributeModule.ko verbose={0,1,2} hook_port={PUERTO_A_INTERCEPTAR} start_redirect_port={PUERTO_INICIAL_REDIRECCION}  number_redirect_ports={NUMERO_DE_PUERTOS_A_REDIRECCIONAR}`

EJ.

`sudo insmod UDPRedistributeModule.ko verbose=2 hook_port=13131 start_redirect_port=1820 number_redirect_ports=4`

Lo cual activa el módulo para redirijir los paquetes hacia el puerto 13131 a los puertos 1820, 1821, 1822 y 1823
