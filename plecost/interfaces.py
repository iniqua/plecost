from enum import Enum
from typing import Union, Type

# Code taken from: https://stackoverflow.com/a/41266737
def metaclass_resolver(*classes):
    metaclass = tuple(set(type(cls) for cls in classes))
    metaclass = metaclass[0] if len(metaclass)==1 \
                else type("_".join(mcls.__name__ for mcls in metaclass), metaclass, {})   # class M_C
    return metaclass("_".join(cls.__name__ for cls in classes), classes, {})              # class C

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class MetaMongo(type):

    def __call__(cls, *args, **kwargs):
        if "_id" in kwargs:
            _id = kwargs.pop("_id")

        o = super().__call__(*args, **kwargs)

        return o

class Serializable(metaclass=MetaMongo):

    def load_enum(self, field_name: str, enum_type: Type):
        if getattr(self, field_name) and \
                type(getattr(self, field_name)) is int:
            setattr(self, field_name, enum_type(getattr(self, field_name)))

    def _clean_dict_(self,
                   data = None,
                   clean_or_raw: str = "clean") -> Union[dict, list, str, int]:

        # DICT
        if type(data) is dict:
            ret = {}

            for x, y in data.items():

                if x.startswith("raw") and clean_or_raw == "clean":
                    continue

                ret[x] = self._clean_dict_(y, clean_or_raw=clean_or_raw)

            return ret

        # LIST
        elif type(data) is list:

            ret = []

            for d in data:
                ret.append(self._clean_dict_(d, clean_or_raw=clean_or_raw))

            return ret

        elif hasattr(data, "clean_dict"):
            return data.clean_dict(clean_or_raw=clean_or_raw)

        elif isinstance(data, Enum):
            return data.value

        else:
            if hasattr(data, "decode"):
                return data.decode()

            return data

    def clean_dict(self,
                   clean_or_raw: str = "clean") -> Union[dict, list, str, int]:
        """removes fields 'raw' from content"""

        return self._clean_dict_(self.__dict__, clean_or_raw=clean_or_raw)


    def raw_dict(self) -> Union[dict, list, str, int]:
        """Dumps all content to valid json file"""
        return self.clean_dict(clean_or_raw="raw")


__all__ = ("Singleton", "Serializable", "metaclass_resolver")
