from prompt_toolkit.lexers import Lexer
from prompt_toolkit.document import Document


class CyberLexer(Lexer):

    COMMANDS = {"set", "use", "run", "show", "exit"}
    TARGET_KEYWORD = {"target"}
    SPECIAL = {"attack_chain"}
    def lex_document(self, document: Document):
        def get_line(lineno):
            words = document.lines[lineno].split()
            tokens = []
            for word in words:
                if word in self.COMMANDS:
                    tokens.append(("class:command", word))
                elif word in self.TARGET_KEYWORD:
                    tokens.append(("class:keyword", word))
                elif word in self.SPECIAL:
                    tokens.append(("class:special", word))
                else:
                    tokens.append(("class:text", word))
                tokens.append(("class:text", " "))
            return tokens
        return get_line