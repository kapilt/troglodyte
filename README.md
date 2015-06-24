# Trogolodyte

Trogolodyte provides for an ssh server that execs bash into arbitrary
containers using the docker client api.


# Why

Best practice in the docker community is to avoid running ssh in your
container. Or is it? 

The reality is that it can be quite useful to be able to ssh into 
container to debug various application behavior.

The flipside is you really don't want to have the additional process per
container to enable that.

Well your in luck, 


