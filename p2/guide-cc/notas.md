# Aproximação  

O servidor envia um nonce ao cliente.
O cliente encripta esse **nonce** com a sua chave privada, gera uma assinatura e envia ao servidor.

O servidor verifica a assinatura e desencripta o **nonce** com a chave pública do cliente.  

