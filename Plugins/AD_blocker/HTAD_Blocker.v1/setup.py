from setuptools import setup, find_packages

setup(
    name="HTAD_Blocker_v1",
    version="1.0.0",
    author="k1ttywnn",
    description="Advanced ad blocking plugin",
    packages=find_packages(),
    package_data={"": ["plugin.json"]},
    python_requires=">=3.6",
)
