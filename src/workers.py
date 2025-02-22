from javax.swing import SwingWorker

class AnalysisWorker(SwingWorker):
    def __init__(self, extender, prompt, response_area):
        SwingWorker.__init__(self)
        self.extender = extender
        self.prompt = prompt
        self.response_area = response_area
        self.worker_cancelled = [False]

    def doInBackground(self):
        try:
            if self.worker_cancelled[0]:
                return "Analysis cancelled by user"
                
            self.extender._callbacks.printOutput(
                "Starting AI analysis (prompt length: {})".format(len(self.prompt))
            )
            result = self.extender.service.analyze(self.prompt)
            self.extender._callbacks.printOutput("Analysis completed")
            return result
            
        except Exception as e:
            self.extender._callbacks.printError("Error in analysis: {}".format(str(e)))
            return "Error: {}".format(str(e))

    def done(self):
        try:
            if not self.worker_cancelled[0]:
                result = self.get()
                self.response_area.setText(result)
                self.response_area.setCaretPosition(0)
        except Exception as e:
            self.extender._callbacks.printError("Error displaying results: {}".format(str(e)))
            self.response_area.setText("Error: {}".format(str(e))) 