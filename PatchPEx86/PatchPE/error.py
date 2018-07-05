class FileError(Exception):
    def __init__(self, value):
        message = '%s isn\'t PE file!' % value
        super(FileError, self).__init__(message)

class SectionError(Exception):
    def __init__(self, value):
        if value.isdigit():
            message = '%s doesn\'t match in binary!' % value
        else:
            message = '\"%s\" section isn\'t in binary!' % value
        super(SectionError, self).__init__(message)
