		20220107/1258

		Status:#idea
		
		Tags:

		# Ubuntu 18.04 LTS Server
		1.  ### Re-generate the RSA and ED25519 keys
    
    rm /etc/ssh/ssh_host_*  
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""  
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
2.  ### Remove small Diffie-Hellman moduli
    
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe  
    mv /etc/ssh/moduli.safe /etc/ssh/moduli
3.  ### Disable the DSA and ECDSA host keys
    
    Comment out the DSA and ECDSA _HostKey_ directives in the _/etc/ssh/sshd_config_ file:  
      
    sed -i 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
4.  ### Restrict supported key exchange, cipher, and MAC algorithms
    
    echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com" >> /etc/ssh/sshd_config
5.  ### Restart OpenSSH server
    
    service ssh restart



		--
		# References
		