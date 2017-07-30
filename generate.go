package clamscan

//TODO: move these to go-based tooling or remove them completely

//go:generate /bin/bash -c "echo -n 'Trojan.Win32.Emold.A:0:*:' > customsig.ndb"
//go:generate /bin/bash -c "cat testfile | sigtool --hex-dump | head -c 2048 >> customsig.ndb"
