# diff msdl link collector

default: release

release:
	pipreqs . --encoding=utf8 --force

localbuild:
	pwsh -command Compress-Archive -Path DiffFrontCollector.py,requirements.txt -DestinationPath MsdlCollector.zip && exit

clean:
	cmd /c del *.log && exit
	cmd /c del MsdlCollector.zip && exit