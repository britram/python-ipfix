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

# This file is not part of the main ipfix distribution; 
# it exists for interactive visualization of IPFIX messages.
# It's basically a sick hack pulled together over a couple of hours.
# It's not documented, and that's intentional.
# It's entirely possible that I'll come back and clean this up one day.

from . import message
from . import template
from . import types

import math

import svgwrite
import string
import random

def scale_tuple(t, scale):
    return tuple([x * s for x,s in zip(t, scale)])

def scale_tupletuple(tt, scale):
    return tuple([scale_tuple(x, scale) for x in tt])

def render_dt8601(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def render_ienumber(ie):
    if ie.pen:
        num = ie.num + 0x8000
    else:
        num = ie.num
    return midtrunc(ie.name,6,4) + "(" + str(num) + ")"

def random_id(length = 16):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for x in range(length))

def midtrunc(s, front, back):
    if len(s) <= (front + back + 3):
        return s
    else:
        return s[:front] + "..." + s[-back:]

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
    
    def __init__(self, raster=8, offset=0):
        self.raster = raster
        self.col = 0
        self.row = 0
        self.fields = []
        self.rowaddrs = [offset]
        self.fill="white"
        
    def set_fill(self, fill):
        self.fill = fill
        
    def _add_field(self, length, field):
        self.fields.append(field)
    
    def _row_extend(self, count):
        for i in range(count):
            self.row += 1
            self.rowaddrs.append(self.rowaddrs[-1] + self.raster)
    
    def add(self, length, value,
            render_fn=str, label=None, rowbreak=False):
        
        # Increment row on rowbreak
        if rowbreak and self.col:
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
                              render_fn(value), label, self.fill))
                self.col += length
            # Case 0b: doesn't fit on row, force rowbreak
            else:
                #print("    short field doesn't fit, force rowbreak")
                self.add(length, value, render_fn, label, True)
    
        # Case 1: flush left but too big to fit
        elif self.col == 0 and length > self.raster:
            # Case 1a: even multiple, multirow rect
            if length % self.raster == 0:
                #print("    perfect fit, multirow rect")
                self._add_field(length, 
                                RectField(self.col, self.row, 
                                          self.raster, length / self.raster,
                                          render_fn(value), label, self.fill))
                self._row_extend(int(length / self.raster))
            # Case 1b: not even multiple, left tetronimo
            else:               
                #print("    long flush left tetronimo")
                self._add_field(length, 
                    LeftPolylineField(self.row, self.raster,
                                      math.ceil(length / self.raster),
                                      length % self.raster,
                                      render_fn(value), label, self.fill))
                self._row_extend(int(math.floor(length / self.raster)))
                self.col = length % self.raster;
                
        # Case 2: flush right
        elif (self.col + length) % self.raster == 0:
            #print("    long flush right tetronimo")
            self._add_field(length,
                RightPolylineField(self.row, self.raster,
                                   math.ceil(length / self.raster),
                                   self.raster - self.col,
                                   render_fn(value), label, self.fill))
            self._row_extend(int(math.ceil(length / self.raster)))
            self.col = 0                       
        
        # Case 3: polyline middle tetronimo; too lazy for this
        # corner case now, bail and force a left tetronimo
        else:
            #print("    too lazy for mid tetronimo, force rowbreak")
            self.add(length, value, render_fn, label, True)

    def _render_fields(self, dwg, origin, scale, fontsize):
        rid = random_id()
        # create a boxgroup to contain the fields
        gb = dwg.g(id="boxes-"+rid, stroke="black", stroke_width=2)
        
        # create a textgroup to contain the fields
        gt = dwg.g(id="text-"+rid, font_size=fontsize)
        
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
        gc = dwg.g(id=random_id(), 
                   font_size=fontsize)
        
        # draw text where appropriate
        for i in range(0, self.raster):
            gc.add(dwg.text(i, ((i + 1) * scale[0] - scale[0]/5, 0),
                            style="text-anchor: right; "
                                  "dominant-baseline: hanging;"))
        
        # use the coladdr group in the drawing
        dwg.defs.add(gc)
        uc = dwg.use(gc, insert = origin)
        dwg.add(uc)

    def _render_rowhdr(self, dwg, origin, scale, fontsize):

        # create a group to contain the row addresses
        gr = dwg.g(id=random_id(), 
                   font_size=fontsize)
                   
        # draw text where appropriate
        for i, a in enumerate(self.rowaddrs):
            gr.add(dwg.text(hex(a), (0, i * scale[1]),
                            style="text-anchor: left; "
                                  "dominant-baseline: hanging;"))
        
        # use the rowaddr group in the drawing
        dwg.defs.add(gr)
        ur = dwg.use(gr, insert = origin)
        dwg.add(ur)
        
    def render(self, scale):
        # new drawing
        dwg = svgwrite.Drawing(size=(scale[0] * (self.raster + 1), 
                                     scale[1] * (self.row + 2)))
        
        # render column header
        self._render_colhdr(dwg, (scale[0], 0), scale, int(scale[1]/1.75))

        # render row header
        self._render_rowhdr(dwg, (0, scale[1]/2), scale, int(scale[1]/1.75))

        # render fields
        self._render_fields(dwg, (scale[0], scale[1]/2), scale, int(scale[1]/2))
        
        # return document
        return dwg.tostring()

def draw_msg_header(ofd, version, length, sequence, export_time, odid):
    ofd.add(2, version, label="Version")
    ofd.add(2, length, label="Length")
    ofd.add(4, sequence, label="Sequence")
    ofd.add(4, export_time, render_fn=render_dt8601, label="Export Time")
    ofd.add(4, odid, label="Observation Domain")
    
def draw_set_header(ofd, setid, setlen):
    ofd.add(2, setid, label="Set ID")
    ofd.add(2, setlen, label="Set Length")

def draw_template(ofd, tmpl, setid=None):
    if not setid:
        setid = tmpl.native_setid()

    ofd.add(2, tmpl.tid, label="ID")
    ofd.add(2, tmpl.count(), label="Count")
    if (setid == template.OPTIONS_SET_ID):
        ofd.add(2, tmpl.scopecount, label="Scope")
    for ie in tmpl.ies:
        ofd.add(2, ie, label="IE", render_fn=render_ienumber)
        ofd.add(2, ie.length, label="Len")
        if ie.pen:
            ofd.add(4, ie.pen, label="PEN")

class MessageBufferRenderer:
    def __init__(self, msg, scale=(90,30), raster=8):
        self.msg = msg
        self.scale = scale
        self.raster = raster
        
        # FIXME this really, really should be done in a stylesheet.
        self.msg_header_fill = "rgb(255,216,216)"
        self.set_header_fill = "rgb(240,192,216)"
        self.template_fill = "rgb(224,224,255)"
        self.record_fill = [ "rgb(255,255,216)",
                             "rgb(216,255,216)" ]

        self.ofd = OctetFieldDrawing(self.raster)
        
    def add_msg_header(self, fill=None):
        if fill:
            self.ofd.set_fill(fill)

        draw_msg_header(self.ofd, 10, self.msg.length, self.msg.sequence, 
                        self.msg.get_export_time(), self.msg.odid)
    
    def add_set_header(self, setid, setlen, fill=None):
        if fill:
            self.ofd.set_fill(fill)
        
        draw_set_header(self.ofd, setid, setlen)

    def add_template(self, tmpl, fill=None, setid=None):
        if fill:
            self.ofd.set_fill(fill)

        draw_template(self.ofd, tmpl, setid=setid)
    
    def add_record_at_offset(self, offset, tmpl, fill=None):
        if fill:
            self.ofd.set_fill(fill)
        
        (values, offset) = tmpl.decode_tuple_from(self.msg.mbuf, offset)
        for v, ie in zip(values, tmpl.ies):
            # prefix with varlen
            if ie.length == types.VARLEN:
                ielen = len(ie.type.valenc(v))
                if ielen > 254:
                    self.ofd.add(1, 255)
                    self.odd.add(2, ielen, label="varlen")
                else:
                    self.ofd.add(1, ielen, label="varlen")
            else:
                ielen = ie.length
            
            if ielen < 2:
                label = midtrunc(ie.name,4,4)
            elif ielen < 4:
                label = midtrunc(ie.name,8,4)
            else:
                label = midtrunc(ie.name,8,8)
            
            self.ofd.add(ielen, v, label=label)
        
        return offset
            
    def render(self, start=0, length=65535):
        # record count for color rotation
        reccount = 0
        
        # start the drawing from scratch
        self.ofd = OctetFieldDrawing(self.raster, start)
        
        # prepare the message for rendering
        self.msg.to_bytes()
        self.msg._scan_setlist()
        
        # dump message header
        if start == 0:
            self.add_msg_header(self.msg_header_fill)

        # iterate the setlist
        for (offset, setid, setlen) in self.msg.setlist:
            # only render sets within the window
            if offset < start:
                continue
            if offset > start + length:
                break
 
            # add set header
            self.add_set_header(setid, setlen, self.set_header_fill)
            
            setend = offset + setlen
            offset += message._sethdr_st.size # skip set header in decode
            if setid == template.TEMPLATE_SET_ID or \
               setid == template.OPTIONS_SET_ID:
                while offset < setend:
                    (tmpl, offset) = template.decode_template_from(
                                              self.msg.mbuf, offset, setid)
                    self.add_template(tmpl, fill=self.template_fill, setid=setid)
            elif setid < 256:
                warn("skipping illegal set id "+str(setid)+" in render")
                
            else:
                try:
                    tmpl = self.msg.templates[(self.msg.odid, setid)]
                    while (offset + tmpl.minlength <= setend) and\
                          (offset < start + length):
                        fill = self.record_fill[reccount % len(self.record_fill)]
                        offset = self.add_record_at_offset(offset, tmpl, fill)
                        reccount += 1

                except KeyError:
                    while offset < setend:
                        self.add_byte(self.msg.mbuf[offset], "white")
                        offset += 1
                
                except EOFError:
                    pass

        return self.ofd.render(self.scale)

class MessageStreamRenderer(MessageBufferRenderer):
    def __init__(self, stream, scale):
        super().__init__(message.MessageBuffer(), scale)
        self.stream = stream
        
    def render_next_message(self, length=65535):
        self.msg.read_message(self.stream)
        # must decode the message to ensure all templates loaded into the TIB
        for rec in self.msg.namedict_iterator():
            pass
        return self.render(length=length)
