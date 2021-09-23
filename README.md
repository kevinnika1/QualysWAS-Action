# QualysWAS-Action

An action to integrate GitHub with the Qualys WAS module so that developers can preform the scan and obtain results within the CI/CD pipeline in GitHub without having to sign into Qualys.

Works by using Qualys APIs to create a scan on a chosen website and then getting the results of this scan in the form of a html report as a GitHub artifact from the pipeline. 
