TAG := "0.4.5"

trigger:
	git commit -am'updated things'
	git push --force
	git tag ${TAG}
	git push --tags --force