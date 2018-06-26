from ..backend import *
from ..patch import *

class DetourBackend(Backend):
    def __init__(self, input_file):
        super(DetourBackend, self).__init__(input_file)

    def apply_patches(self, patches):
        pass
