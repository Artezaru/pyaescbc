# Copyright 2025 Artezaru
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Best-effort wiping of secrets held in a ``bytearray``.
"""


def delete_bytearray(barray: bytearray) -> None:
    r"""
    Overwrites the contents of a bytearray with zeros, then empties it.

    After the call, ``barray`` is an empty bytearray (``len(barray) == 0``); the object
    itself still exists. If the bytearray cannot be resized because a ``memoryview`` on
    it is still open, its contents are zeroed but its length is kept.

    .. note::

        Wiping is best-effort: Python and the underlying libraries may have made
        immutable copies of the data, which cannot be erased.

    .. code-block:: python

        import pyaescbc

        key = pyaescbc.generate_key()
        ...
        pyaescbc.delete_bytearray(key)   # key == bytearray()

    Parameters
    ----------
    barray : bytearray
        The bytearray to wipe.

    Raises
    ------
    TypeError
        If the given argument is not a ``bytearray`` instance.
    """
    if not isinstance(barray, bytearray):
        raise TypeError('Parameter barray is not bytearray instance.')

    # Overwrite in place (same length: no reallocation, works even with open memoryviews)
    barray[:] = bytes(len(barray))

    # Then empty it; impossible while a memoryview is open, but the data is already gone
    try:
        barray.clear()
    except BufferError:
        pass
