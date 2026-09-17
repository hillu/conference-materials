
-- Taken from http://lua-users.org/wiki/BaseSixtyFour
local b ='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
-- encoding
function enc(data)
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

return {
   {
      -- Recode SVG images from embedded <svg> … </svg> into
      -- <img data-src="data:image/svg+xml;base64, … ">
      Image = function (elem)
	 if elem.src:match("%.svg$") then
	    local mime_type, contents = pandoc.mediabag.fetch(elem.src)
	    if mime_type == 'image/svg+xml' and contents then
	       elem.src = "data:" .. mime_type .. ";base64," .. enc(contents)
	       return elem
	    end
	 end
	 return elem
      end
   }
}
