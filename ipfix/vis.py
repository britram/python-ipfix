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
import math

import svgwrite

def scale_tuple(t, factor):
    return tuple([x * factor for x in t])

def scale_tupletuple(tt, factor):
    return tuple([scale_tuple(x, factor) for x in tt])

class OctetField:
    def __init__(self, origin, size, value, label, fill):
        self.origin = origin;
        self.size = size;
        self.value = value
        self.label = label
        self.fill = fill
        self.textorigin = (origin[0] + size[0] / 2, origin[1] + size[1] / 2)

    def text(self):
        if (self.label):
            return str(self.label)+": "+str(self.value)
        else:
            return str(self.value)

class RectField(OctetField):
    def __init__(self, col, row, width, height, value, label, fill):
        origin = (col, row)
        size = (width, height)
        super().__init__(origin, size, value, label, fill)
        
    def add_box_to_drawing(self, g, dwg, scale):
        g.add(dwg.rect(insert = scale_tuple(self.origin, scale), 
                       size = scale_tuple(self.size, scale), 
                       fill = self.fill))

    def add_text_to_drawing(self, g, dwg, scale):
        g.add(dwg.text(self.text(), scale_tuple(self.textorigin, scale), 
                       style="text-anchor: middle; "
                             "dominant-baseline: hanging;"))

class PolylineField(OctetField):
    def __init__(self, points, origin, size, value, label, fill):
        super().__init__(origin, size, value, label, fill)
        self.points = points

    def add_box_to_drawing(self, g, dwg, scale):
        g.add(dwg.polyline(scale_tupletuple(self.points, scale),
                           fill = self.fill))

    def add_text_to_drawing(self, g, dwg, scale):
        g.add(dwg.text(self.text(), scale_tuple(self.textorigin, scale), 
                       style="text-anchor: middle; "
                             "dominant-baseline: hanging;"))

class LeftPolylineField(PolylineField):
    def __init__(self, row, width, height, botwidth, 
                 value, label, fill):
        points = ((0, row), 
                  (width, row), 
                  (width, row + height - 1),
                  (botwidth, row + height - 1),
                  (botwidth, row + height),
                  (0, row + height),
                  (0, row))
        origin = (0, row)
        size = (width, height-1)
        super().__init__(points, origin, size, value, label, fill)

class RightPolylineField(PolylineField):
    def __init__(self, row, width, height, topwidth, 
                 value, label, fill):
        points = ((width - topwidth, row),
                  (width, row),
                  (width, row + height),
                  (0, row + height),
                  (0, row + 1),
                  (width - topwidth, row + 1),
                  (width - topwidth, row))
        origin = (0, row+1)          
        size = (width, height-1)
        super().__init__(points, origin, size, value, label, fill)        

class MidPolylineField(PolylineField):
    def __init__(self, row, width, height, topwidth, botwidth, 
                 value, label, fill):
        points = ((width - topwidth, row),
                  (width, row),
                  (width, row + height - 1),
                  (botwidth, row + height - 1),
                  (botwidth, row + height),
                  (0, row + height),
                  (0, row + 1),
                  (width - topwidth, row + 1),
                  (width - topwidth, row))
        origin = (0, row+1)
        size = (width, height-2)
        super().__init__(points, origin, size, value, label, fill)   

class OctetFieldDrawing:     
    
    def __init__(self, raster=8):
        self.raster = raster
        self.col = 0
        self.row = 0
        self.fields = []
        self.rowaddrs = [0]
        
    def _add_field(self, length, field):
        self.fields.append(field)
    
    def _row_extend(self, count):
        for i in range(count):
            self.row += 1
            self.rowaddrs.append(self.rowaddrs[-1] + self.raster)
    
    def add(self, length, value,
            render_fn=hex, label=None, fill="white", rowbreak=False):
        
        # Increment row on rowbreak
        if rowbreak:
            self.row += 1
            self.rowaddrs.append(self.rowaddrs[-1] + self.col)
            self.col = 0
        
        #print ("draw field length "+str(length)+
        #       " at ("+str(self.col)+", "+str(self.row)+")")
        
        # Case 0: could fit on a single row
        if length <= self.raster:
            # Case 0a: fits on row, simple rect
            if (self.col + length) <= self.raster:
                #print("    fit, simple rect")
                self._add_field(length, 
                    RectField(self.col, self.row, length, 1, 
                              render_fn(value), label, fill))
                self.col += length
            # Case 0b: doesn't fit on row, force rowbreak
            else:
                #print("    short field doesn't fit, force rowbreak")
                self.add(length, value, render_fn, label, fill, True)
    
        # Case 1: flush left but too big to fit
        elif self.col == 0 and length > self.raster:
            # Case 1a: even multiple, multirow rect
            if length % self.raster == 0:
                #print("    perfect fit, multirow rect")
                self._add_field(length, 
                                RectField(self.col, self.row, 
                                          self.raster, length / self.raster,
                                          render_fn(value), label, fill))
                self._row_extend(length / self.raster)
            # Case 1b: not even multiple, left tetronimo
            else:               
                #print("    long flush left tetronimo")
                self._add_field(length, 
                    LeftPolylineField(self.row, self.raster,
                                      math.ceil(length / self.raster),
                                      length % self.raster,
                                      render_fn(value), label, fill))
                self._row_extend(int(math.floor(length / self.raster)))
                self.col = length % self.raster;
                
        # Case 2: flush right
        elif (self.col + length) % self.raster == 0:
            #print("    long flush right tetronimo")
            self._add_field(length,
                RightPolylineField(self.row, self.raster,
                                   math.ceil(length / self.raster),
                                   self.raster - self.col,
                                   render_fn(value), label, fill))
            self._row_extend(int(math.ceil(length / self.raster)))
            self.col = 0                       
        
        # Case 3: polyline middle tetronimo; too lazy for this
        # corner case now, bail and force a left tetronimo
        else:
            #print("    too lazy for mid tetronimo, force rowbreak")
            self.add(length, value, render_fn, label, fill, True)

    def _render_fields(self, dwg, origin, scale, fontsize):
        # create a boxgroup to contain the fields
        gb = dwg.g(id="boxes", stroke="black", stroke_width=2)
        
        # create a textgroup to contain the fields
        gt = dwg.g(id="text", font_size=fontsize)
        
        # add each field to the group
        for field in self.fields:
            field.add_box_to_drawing(gb, dwg, scale)
            field.add_text_to_drawing(gt, dwg, scale)
        
        # use the groups in the drawing
        dwg.defs.add(gb)
        ub = dwg.use(gb, insert=origin)
        dwg.add(ub)
        
        dwg.defs.add(gt)
        ut = dwg.use(gt, insert=origin)
        dwg.add(ut)
        
    def _render_colhdr(self, dwg, origin, scale, fontsize):
        # create a group to contain the column addresses
        gc = dwg.g(id="coladdr", 
                   font_size=fontsize)
        
        # draw text where appropriate
        for i in range(0, self.raster):
            gc.add(dwg.text(i, ((i + 1) * scale - scale/4, 0),
                            style="text-anchor: right; "
                                  "dominant-baseline: hanging;"))
        
        # use the coladdr group in the drawing
        dwg.defs.add(gc)
        uc = dwg.use(gc, insert = origin)
        dwg.add(uc)

    def _render_rowhdr(self, dwg, origin, scale, fontsize):

        # create a group to contain the row addresses
        gr = dwg.g(id="rowaddr", 
                   font_size=fontsize)
                   
        # draw text where appropriate
        for i, a in enumerate(self.rowaddrs):
            gr.add(dwg.text(hex(a), (0, i * scale),
                            style="text-anchor: left; "
                                  "dominant-baseline: hanging;"))
        
        # use the rowaddr group in the drawing
        dwg.defs.add(gr)
        ur = dwg.use(gr, insert = origin)
        dwg.add(ur)
        
    def render(self, scale):
        # new drawing
        dwg = svgwrite.Drawing(size=(scale * (self.raster + 1), 
                                     scale * (self.row + 2)))
        
        # render column header
        self._render_colhdr(dwg, (scale, 0), scale, 18)

        # render row header
        self._render_rowhdr(dwg, (0, scale/3), scale, 18)

        # render fields
        self._render_fields(dwg, (scale, scale/3), scale, 18)
        
        # return document
        return dwg.tostring()
       
class VisualMessageBuffer(message.MessageBuffer):
    def __init__(self):
        super().__init__()
        
