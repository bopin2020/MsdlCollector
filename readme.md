# msdlcollector
> Windows msdl link collector

## how to use
```
python -m pip install -r requirements.txt

python DiffFrontCollector.py -i

// Windows update and restart your Windows

python DiffFrontCollector.py --diff
```

> when you execute --diff features, it will generate a list of old-new msdl link and override registry value
> if you dont wanna this, try with --disableupdate