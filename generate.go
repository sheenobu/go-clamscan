package clamscan

//TODO: move these to go-based tooling or remove them completely

//go:generate /bin/sh -c "echo -n 'Trojan.Win32.Emold.A:1:*:' > customsig.ndb"
//go:generate /bin/sh -c "cat testfile | sigtool --hex-dump | head -c 2048 >> customsig.ndb"
