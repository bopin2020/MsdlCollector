# diff msdl link collector

default: release

release:
	pipreqs . --encoding=utf8 --force


clean:
	del *.log