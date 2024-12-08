TAG := "0.4.5"

trigger:
	git commit -am'updated things'
	git tag ${TAG}
	git push
	git push --tags