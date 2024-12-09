TAG := "0.4.5"

trigger:
	git commit -am'updated things' --allow-empty
	git push --force
	git tag ${TAG} --force
	git push --tags --force