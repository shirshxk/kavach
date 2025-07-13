from PyQt5.QtCore import QObject, pyqtSignal

class VerdictEmitter(QObject):
    verdict_signal = pyqtSignal(dict)

verdict_emitter = VerdictEmitter()
