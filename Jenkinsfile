#!/usr/bin/env groovy
@Library('pipeline-library')_

def repoName = "signingExamples"
def dependencyRegex = "itextcore"
//JDK8 is required for pkcs11 module
def jdkVersion = "jdk-8-oracle"

automaticJavaBuild(repoName, dependencyRegex, jdkVersion)
