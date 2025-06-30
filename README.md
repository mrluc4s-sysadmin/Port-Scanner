Usage:
		portscanner.py [-h] [-sS | -sF | -sA] [-p PORT_RANGE] ip

	Network Port Scanner.
	
	Syntaxe: python3 portscanner.py [target] [scan_type] [port_range]
	
		ex: sudo python3 portscanner.py scanme.nmap.org -p 22-80
		    sudo python3 portscanner.py scanme.nmap.org -p 80 -sF ou -sA
		    	

	positional arguments:
	  ip                    Endereço IP ou hostname do alvo (ex: python3 portscanner.py 192.168.0.1 | python3 portscanner.py google.com)

	options:
	  -h, --help            mensagem de ajuda
	  -sS                   Syn scan, varredura default do sistema enviando pacotes TCP com a flag SYN
	  -sF                   Fin scan, varredura "furtiva" do sistema, utilizada para evadir firewall, enviando pacotes TCP com a flag FIN
	  -sA                   Ack scan, varredura utiliza para mapear padrões de regras de firewall, enviando pacotes TCP com a flag ACK
	  -p PORT_RANGE, --ports PORT_RANGE	Intervalo de portas a ser varridas (ex: 80-1200), default: 1-1024, ou apenas 1 porta (ex: -p 80)
		                
