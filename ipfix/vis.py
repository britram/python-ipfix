#
# python-ipfix (c) 2013 Brian Trammell.
#
# Many thanks to the mPlane consortium (http://www.ict-mplane.eu) for
# its material support of this effort.
# 
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#

from . import message
import svgwrite
import math

class OctetFieldDrawing:
    
    class OctetField:
        def __init__(self, value, label, fill):
            self.value = value
            self.label = label
            self.fill = fill
    
    class RectField(OctetField):
        def __init__(self, col, row, width, height, value, label, fill):
            super().__init__(value, label, fill)
            self.origin = (col, row)
            self.size = (width, height)
    
    class PolylineField(OctetField):
        def __init__(self, points, size, value, label, fill):
            super().__init__(value, label, fill)
            self.points = points
    
    class LeftPolylineField(PolylineField):
        def __init__(self, row, width, height, botwidth, value, label, fill):
            points = ((0, row), 
                      (width, row), 
                      (width, row + height - 1),
                      (botwidth, row + height - 1),
                      (botwidth, row + height),
                      (0, row + height),
                      (0, row))
            size = (width, height)
            super().__init__(points, size, value, label, fill)
    
    class RightPolylineField(PolylineField):
        def __init__(self, row, width, height, topwidth, value, label, fill):
            points = ((width - topwidth, row),
                      (width, row),
                      (width, row + height),
                      (0, row + height),
                      (0, row + 1),
                      (width - topwidth, row + 1),
                      (width - topwidth, row))
            size = (width, height)
            super().__init__(points, size, value, label, fill)        

    class MidPolylineField(PolylineField):
        def __init__(self, row, width, height, topwidth, botwidth, value, label, fill):
            points = ((width - topwidth, row),
                      (width, row),
                      (width, row + height - 1),
                      (botwidth, row + height - 1),
                      (botwidth, row + height),
                      (0, row + height),
                      (0, row + 1),
                      (width - topwidth, row + 1),
                      (width - topwidth, row))
            size = (width, height)
            super().__init__(points, size, value, label, fill)        
    
    def __init__(self):
        self.col = 0
        self.row = 0
        self.fields = []
        
    def add(self, length, value,
            render_fn=hex, label=None, fill=(255,255,255), rowbreak=False):
        
        # Increment row on rowbreak
        if rowbreak:
            self.col = 0
            self.row += 1
        
        # Case 0: fits on row
        if (self.col + length) <= self.raster:
            self.fields.append(RectField(self.col, self.row, length, 1, 
                                         render_fn(value), label, fill))
    
        # Case 1: doesn't fit on row, shorter than row: 
        # bail, force rowbreak and try again
        elif length < self.raster:
            self.add(length, value, render_fn, label, fill, True)
    
        # Case 2: multirow rect
        elif self.col == 0 and length > self.raster \
                           and length % self.raster == 0:
            self.fields.append(RectField(self.col, self.row, 
                                         self.raster, length / self.raster,
                                         render_fn(value), label, fill))
                                     
        # Case 3: polyline left tetronimo
        elif self.col == 0:
            self.fields.append(
                LeftPolylineField(self.row, self.raster,
                                  math.ceil(length / self.raster),
                                  length % self.raster,
                                  render_fn(value), label, fill))
        
        # Case 4: polyline right tetronimo
        elif (self.col + length) % self.raster == 0:
            self.fields.append(
                RightPolylineField(self.row, self.raster,
                                   math.ceil(length / self.raster),
                                   self.raster - self.col,
                                   render_fn(value), label, fill))
        
        # Case 5: polyline middle tetronimo; too lazy for this
        # corner case now, bail and force a left tetronimo
        else:
            self.add(length, value, render_fn, label, fill, True)


   
class VisualMessageBuffer(message.MessageBuffer):
    def __init__(self):
        super().__init__()
        
