		20220107/1253

		Status:#idea
		
		Tags:

		# ## Ubuntu 20.04 LTS Server Last modified: July 27, 2020
		Note: all commands below are to be executed as the _root_ user.

	
1.  ### Re-generate the RSA and ED25519 keys
    
    rm /etc/ssh/ssh_host_*  
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""  
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
2.  ### Remove small Diffie-Hellman moduli
    
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe  
    mv /etc/ssh/moduli.safe /etc/ssh/moduli
3.  ### Enable the RSA and ED25519 keys
    
    Enable the RSA and ED25519 _HostKey_ directives in the _/etc/ssh/sshd_config_ file:  
      
    sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
4.  ### Restrict supported key exchange, cipher, and MAC algorithms
    
    echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf
5.  ### Restart OpenSSH server
    
    service ssh restart


		--
		# References
		