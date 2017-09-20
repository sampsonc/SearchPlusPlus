/*
 * The MIT License
 *
 * Copyright 2017 Carl Sampson <chs@chs.us>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package search;

/**
 *
 * @author Carl Sampson <chs@chs.us>
 */
public class ScanMatch implements Comparable<ScanMatch>
{
    private final Integer start;
    private final int end;
    private final String match;
    private final String type;
    private String severity;

    public ScanMatch(String match, int start, int end, String type)
    {
        this.start = start;
        this.end = end;
        this.match = match.replace("<", "&lt;").replace(">", "&gt;");
        this.type = type;
    }

    public int getStart()
    {
        return this.start;
    }

    public int getEnd()
    {
        return this.end;
    }

    public String getMatch()
    {
        return this.match;
    }

    public String getType()
    {
        return this.type;
    }

    @Override
    public int compareTo(ScanMatch m)
    {
        return this.start.compareTo(Integer.valueOf(m.getStart()));
    }
}
