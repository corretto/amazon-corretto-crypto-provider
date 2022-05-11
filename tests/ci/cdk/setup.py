import setuptools


with open("README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="ACCP CI",
    version="0.0.1",

    description="ACCP CI python environment.",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="ACCP",

    package_dir={"": "cdk"},
    packages=setuptools.find_packages(where="cdk"),

    install_requires=[
        # CDK dependencies.
        "aws-cdk.core==1.97.0",
        "aws-cdk.aws-codebuild==1.97.0",
        "aws-cdk.aws-ecr==1.97.0",
        "aws-cdk.aws-iam==1.97.0",
        # PyYAML is a YAML parser and emitter for Python. Used to read build_spec.yaml.
        "pyyaml==5.3.1",
        # A formatter for Python code.
        "yapf==0.30.0",
    ],

    python_requires=">=3.6",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "License :: OSI Approved :: Apache Software License",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
