# msdlcollector
> Windows msdl link collector

```
usage: start info [-h] [-d TARGET_DIRS [TARGET_DIRS ...]] [-n {0,1,2,3}] [-i] [-u] [-p] [--diff] [--disableupdate] [-s] [-v]

diff msdl collector

options:
  -h, --help            show this help message and exit
  -d TARGET_DIRS [TARGET_DIRS ...], --dirs TARGET_DIRS [TARGET_DIRS ...]
  -n {0,1,2,3}, --num {0,1,2,3}
                        0 system32 | 1 system32\drivers | 2 defender
  -i, --install         first collect msdl link information and push them into registry HKCU\msdlcollector
  -u, --uninstall       remove the specified registry
  -p, --peek            default file name (windows latest version)
  --diff                collect msdl link in real time and diff with registry which output a pair of old-new links (decompilation diff
                        pending item)
  --disableupdate       dont override registry value when changes
  -s, --store           auto store to register msdlcollector\store\year-month
  -v, --verbose         output the verbose information

end information
```

## update


## how to use
```
python -m pip install -r requirements.txt

python DiffFrontCollector.py -i

// Windows update and restart your Windows

python DiffFrontCollector.py --diff
```

> query the store files 
```
python .\DiffFrontCollector.py --enum
python .\DiffFrontCollector.py --query 2025-3 --queryfilter .sys
```

> when you execute --diff features, it will generate a list of old-new msdl link and override registry value
> if you dont wanna this, try with --disableupdate
> -s --store   auto backup diff link results 