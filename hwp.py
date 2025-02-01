import win32com.client as win32com
import win32gui


class Problem:
    def __init__(self, KeyIndicator, pos):
        self.result = KeyIndicator[0]
        self.seccnt = KeyIndicator[1]
        self.sec = KeyIndicator[2]
        self.page = KeyIndicator[3]
        self.col = KeyIndicator[4]
        self.line = KeyIndicator[5]
        self._pos = KeyIndicator[6]
        self.over = KeyIndicator[7]
        self.pos = pos


class Problems:
    def __init__(self):
        self.probNo = 0
        self.probs = []

    def add(self, KeyIndicator, pos):
        self.probNo = self.probNo + 1
        self.probs.append(Problem(KeyIndicator, pos))


class Instance:
    def __init__(self):
        self.n = 0
        self.ins = {}

    def add(self, ins):
        self.ins[self.n] = ins
        self.n = self.n + 1


class HwpHandle:
    def __init__(self):
        self.hwp = win32com.gencache.EnsureDispatch('HWPFrame.HwpObject')
        # TODO: Installing registry key and value for using auto-macro mode.
        # Installing in HKEY_CURRENT_USER\\SOFTWARE\\HNC\\HwpAutomation\\Modules\\FilePathCheck
        self.hwp.RegisterModule('FilePathCheckDLL', 'FilePathCheck')
        self.hwp.SetMessageBoxMode(0x00020000)
        self.instance = Instance()
        self.problems = Problems()
        self.curCtrl = None
        self.colWidth = 0
        self.startPage = 4
        self.curPage = self.startPage

    def open(self, file=None, visible=False):
        if self.instance.n == 0:
            self.hwp.Open(file)
        elif file is None:
            self.hwp.XHwpDocuments.Add(1)
        else:
            # Adding a tab for non-visible instance
            self.hwp.XHwpDocuments.Add(1)
            self.hwp.Open(file)

        if visible:
            self.show()

        self.instance.add(file)
        # Initializing position of caret to the beginning of document.
        self.hwp.MovePos(2)

    def run(self, command):
        self.hwp.Run(command)

    def getCurPage(self):
        return self.hwp.KeyIndicator()[3]

    def getCurCol(self):
        return self.hwp.KeyIndicator()[4]

    def getCurLine(self):
        return self.hwp.KeyIndicator()[5]

    def goPage(self, page):
        self.hwp.HAction.GetDefault("Goto", self.hwp.HParameterSet.HGotoE.HSet)
        self.hwp.HParameterSet.HGotoE.SetSelectionIndex = 1
        self.hwp.HParameterSet.HGotoE.HSet.SetItem("DialogResult", page)
        self.hwp.HAction.Execute("Goto", self.hwp.HParameterSet.HGotoE.HSet)

    def copyPage(self, pageNo):
        self.goPage(pageNo)
        self.run("CopyPage")

    def pastePage(self, pageNo):
        self.goPage(pageNo)
        self.run("PastePage")

    def replaceAll(self, old, new):
        self.hwp.HAction.GetDefault("AllReplace", self.hwp.HParameterSet.HFindReplace.HSet)
        option = self.hwp.HParameterSet.HFindReplace
        option.FindString = old
        option.ReplaceString = new
        option.IgnoreMessage = 1
        self.hwp.HAction.Execute("AllReplace", self.hwp.HParameterSet.HFindReplace.HSet)

    def active(self, ins):
        self.hwp.XHwpDocuments.Item(ins).SetActive_XHwpDocument()

    def show(self, val=True):
        self.hwp.XHwpWindows.Active_XHwpWindow.Visible = val

    def findEndnote(self, probNo):
        headCtrl = self.hwp.HeadCtrl
        curlCtrl = headCtrl
        beginCtrl = None
        nextCtrl = None
        cnt = 1

        while curlCtrl:
            # Searching only "EndNote" ctrl
            if curlCtrl.CtrlID == "en":
                if cnt == probNo:
                    beginCtrl = curlCtrl
                elif cnt == probNo+1:
                    nextCtrl = curlCtrl
                    break
                cnt += 1
            curlCtrl = curlCtrl.Next

        return beginCtrl, nextCtrl

    def copyProb(self, ins, probNo):
        self.active(ins)

        cur, next = self.findEndnote(probNo)

        curPos = cur.GetAnchorPos(0)
        self.hwp.SetPos(curPos.Item("List"), curPos.Item("Para"), curPos.Item("Pos"))
        curPage = self.getCurPage()

        # Handling exception of the last problem which hasn't next endnote.
        if next == None:
            nextPage = 0xffffffff
        else:
            nextPos = next.GetAnchorPos(0)
            self.hwp.SetPos(nextPos.Item("List"), nextPos.Item("Para"), nextPos.Item("Pos"))
            nextPage = self.getCurPage()

        # Copying to end of current page if the next problem's page is over the current page.
        # ISSUE: If the problem overflows to the next page in real, in this case, it won't be going normally.
        if nextPage > curPage:
            self.hwp.SetPos(curPos.Item("List"), curPos.Item("Para"), curPos.Item("Pos"))
            self.run("MovePageEnd")

            nextPos = self.hwp.GetPos()
            self.hwp.SelectText(curPos.Item("Para"), curPos.Item("Pos"), nextPos[1], nextPos[2])
        else:
            # Copying from end of current endnote to beginning of next endnote.
            self.hwp.SelectText(curPos.Item("Para"), curPos.Item("Pos"), nextPos.Item("Para"), nextPos.Item("Pos"))

        self.run("Copy")
        self.setStyle()

    # Fitting differences between document textbox's size
    # ISSUE: It is hard to figure out what "Gso" Ctrl should be modified.
    def reSizegso(self):
        if self.curCtrl == None:
            self.curCtrl = self.hwp.HeadCtrl

        curPos = self.hwp.GetPos()
        curCtrl = self.curCtrl

        while curCtrl:
            if curCtrl.CtrlID == "gso":
                gsoPos = curCtrl.GetAnchorPos(0)
                self.hwp.SetPos(gsoPos.Item("List"), gsoPos.Item("Para"), gsoPos.Item("Pos"))

                if(curCtrl.HasList and self.hwp.KeyIndicator()[3] >= self.startPage):
                    set = curCtrl.Properties
                    width = set.Item("Width")
                    height = set.Item("Height")
                    parentCtrl = self.hwp.ParentCtrl

                    if (width < self.colWidth and width > (self.colWidth / 2)) and parentCtrl == None:
                        ratio = self.colWidth / width
                        new_height = int(height / ratio)

                        self.hwp.FindCtrl()
                        self.hwp.HAction.GetDefault("ShapeObjDialog", self.hwp.HParameterSet.HShapeObject.HSet)
                        option = self.hwp.HParameterSet.HShapeObject
                        option.Width = self.colWidth
                        option.Height = new_height
                        option.HSet.SetItem("ShapeType", 1)
                        self.hwp.HAction.Execute("ShapeObjDialog", self.hwp.HParameterSet.HShapeObject.HSet)

            self.curCtrl = curCtrl
            curCtrl = curCtrl.Next

        self.hwp.SetPos(curPos[0], curPos[1], curPos[2])

    def pasteProb(self):
        self.active(self.instance.n-1)
        self.goPage(self.curPage)
        self.run("MoveTopLevelEnd")
        self.run("Paste")
        self.reSizegso()

    def colFitting(self):
        while self.hwp.GetPos()[2] == 0:
            self.run("DeleteBack")
        # ISSUE: If the problem ends up at the last page's line, "breakline" moves caret to next page, so an error occurred.
        # self.run("BreakPara")

        curPos = self.hwp.GetPos()
        curLine = self.getCurLine()
        curCol = self.getCurCol()

        if self.problems.probNo == 0:
            self.problems.add(self.hwp.KeyIndicator(), self.hwp.GetPos())
        else:
            prevPos = self.problems.probs[self.problems.probNo-1].pos
            prevCol = self.problems.probs[self.problems.probNo-1].col
            prevLine = self.problems.probs[self.problems.probNo-1].line
            self.hwp.SetPos(prevPos[0], prevPos[1], prevPos[2])

            # If the sum of two problems' lines is over 32(37 is common total line of column and 5 is for the linebreak), next problem will be copied to next column.
            # If the previous and the one before the previous are in the same page, next problem will be copied to next column.
            if (curLine + 5 > 37) or (prevCol != curCol) or (self.problems.probNo >= 2 and self.problems.probs[self.problems.probNo-2].col == prevCol):
                self.run("BreakColumn")
                self.run("MoveListEnd")
                self.setStyle()
            else:
                if curLine > 19:
                    for n in range(10):
                        self.run("BreakPara")
                else:
                    for n in range(18 - prevLine):
                        self.run("BreakPara")

                prevPos = self.hwp.GetPos()
                prevCol = self.getCurCol()
                prevPage = self.getCurPage()

                self.run("MoveListEnd")
                #self.setStyle()

                curCol = self.getCurCol()
                curPage = self.getCurPage()

                if prevCol != curCol or prevPage != curPage:
                    self.hwp.SetPos(prevPos[0], prevPos[1], prevPos[2])
                    for i in range(n):
                        self.run("DeleteBack")
                    self.run("BreakColumn")

            self.run("MoveListEnd")
            self.problems.add(self.hwp.KeyIndicator(), self.hwp.GetPos())
            self.curPage = self.getCurPage()

    def copyTemplate(self):
        self.active(self.instance.n-1)
        self.run("SelectAll")
        self.run("Copy")
        self.run("Cancel")
        self.hwp.MovePos(2)
        self.open()
        self.run("Paste")
        self.hwp.MovePos(2)

    def insertPage(self):
        self.active(self.instance.n-2)
        # TODO: Figuring out the template page number for copying and editing.
        self.copyPage(3)
        self.active(self.instance.n-1)
        self.goPage(self.curPage)
        self.run("BreakPage")
        self.goPage(self.curPage-1)
        self.run("PastePage")

        self.curPage = self.curPage + 1

    def clear(self):
        curCol = self.getCurCol()
        if curCol == 1:
            self.run("BreakColumn")
            self.run("BreakColumn")
        else:
            self.run("BreakColumn")
        # Initializing for the next problems file
        self.problems = Problems()
        
        self.curPage = self.getCurPage()

    def save(self):
        self.hwp.Save()

    def saveAs(self, filename):
        self.hwp.SaveAs(filename)

    def quit(self):
        self.hwp.Quit()

    # TODO: Make sure that example of template to general.
    def changeTemplate(self, month, week, grade, classname, name):
        self.replaceAll("ㅇㅇ월 ㅇ주차", f"{month}월 {week}주차")
        self.replaceAll("ㅇㅇ ㅇㅇ반", f"{grade} {classname}")
        self.replaceAll("이름 : ㅇㅇㅇ", f"이름 : {name}")

    def changePage(self, day, subjectname):
        self.replaceAll("ㅇ요일 숙제", f"{day}요일 숙제")
        self.replaceAll("숙제명", f"{subjectname}")

    # Using for "reSizegso" to fitting textbox's width to column's width
    def getColWidth(self):
        # Moving on column page to get "colWidthGap"
        self.goPage(self.startPage)
        act = self.hwp.CreateAction("PageSetup")
        set = act.CreateSet()
        act.GetDefault(set)

        paperWidth = set.Item("PageDef").Item("PaperWidth")
        lMargin = set.Item("PageDef").Item("LeftMargin")
        rMargin = set.Item("PageDef").Item("RightMargin")

        width = paperWidth - lMargin - rMargin

        act = self.hwp.CreateAction("MultiColumn")
        set = act.CreateSet()
        act.GetDefault(set)

        colWidthGap = set.Item("SameGap")
        width = width - colWidthGap

        self.colWidth = int(width / 2)
        self.hwp.MovePos(2)
    
    def setStyle(self):
        self.run("SelectAll")
        self.run("StyleShortcut1")
        self.run("Cancel")
    
def go(i):
    hwp = HwpHandle()

    #hwp.open("C:\\Users\\saber\\Downloads\\HWP\\test1.hwp")
    hwp.open("C:\\Users\\saber\\Downloads\\HWP\\test2.hwp")
    hwp.open("C:\\Users\\saber\\Downloads\\HWP\\test3.hwp")
    hwp.open("C:\\Users\\saber\\Downloads\\HWP\\template.hwpx")
    # Using this instance for saving notes of the wrong answer.
    hwp.copyTemplate()
    hwp.getColWidth()
    
    #hwp.show()

    problems1 = [1, 5, 12, 14, 18, 20, 24, 27, 30, 31, 34, 38]
    problems2 = [x for x in range(1, 30)]
    problems3 = [4, 16, 31, 34, 77]

    hwp.changePage("화", "테스트1 입니다")

    for prob in problems1:
        hwp.copyProb(0, prob)
        hwp.pasteProb()
        hwp.colFitting()

    hwp.clear()

    hwp.insertPage()
    hwp.changePage("수", "테스트2 입니다")

    for prob in problems2:
        hwp.copyProb(1, prob)
        hwp.pasteProb()
        hwp.colFitting()

    hwp.clear()

    '''    
    hwp.insertPage()
    hwp.changePage("목", "테스트3 입니다")

    for prob in problems3:
        hwp.copyProb(2, prob)
        hwp.pasteProb()
        hwp.colFitting()
    
    hwp.clear()
    '''

    hwp.changeTemplate("1", "1", "고1", "의대반", "천준상")
    hwp.saveAs(f"C:\\Users\\saber\\Downloads\\HWP\\result{i}.hwp")

    hwp.quit()


def main():
    import multiprocessing, time

    start = time.time()

    go(1)

    end = time.time()
    print(end - start)


if __name__ == '__main__':
    main()