#!/usr/bin/python

import argparse
import cmd
import codecs
import configparser
import datetime
import json
import sys
import textwrap
import uuid

config = configparser.ConfigParser()
config_location = "etc/defaults.cfg"
sd = {}


def add_argument(con_text=None, prem_text=None, con_id=None, prem_id=None):
    """
    Syntactic sugar to create an argument structure from a set of texts.
    Given a conclusion text & a list of premise texts, create an intermediate,
    default "support" scheme.
    This makes it easier to build a SADFace document without manually creating
    and organising individual nodes.
    Returns an argument dict, e.g.
    {
        "conclusion": atom,
        "scheme": atom,
        "premises": [atom(s)]
    }
    Returns: a dict
    """
    if ((con_text is not None or con_id is not None) and (prem_text is not None or prem_id is not None)):

        if con_text is not None:
            c = add_atom(con_text)
        else:
            c = get_atom(con_id)

        s = add_scheme("support")
        try:
            add_edge(s["id"], c["id"])
        except Exception as ex:
            print()
            ex
            raise Exception("Could not create new argument")

        p_list = []
        if (prem_text is not None):
            for text in prem_text:
                atom = add_atom(text)
                p_list.append(atom["id"])
                try:
                    add_edge(atom["id"], s["id"])
                except Exception as ex:
                    print()
                    ex
                    raise Exception("Could not create new argument")
        if (prem_id is not None):
            for atom_id in prem_id:
                atom = get_atom(atom_id)
                p_list.append(atom["id"])
                try:
                    add_edge(atom["id"], s["id"])
                except Exception as ex:
                    print()
                    ex
                    raise Exception("Could not create new argument")

        arg = {"conclusion": c, "scheme": s, "premises": p_list}
        return arg
    return None


def add_conflict(arg_text=None, arg_id=None, conflict_text=None, conflict_id=None):
    """
    Conflicts play an important role in arguments. We depict conflict
    through the use of schemes that represent the conflict relationship. This
    function will instantiate a conflict scheme between two nodes (either
    pre-existing & identifed by node IDs or created from supplied texts, or a
    mixture of the two).
    Returns a conflict dict, e.g.
    {
        "argument": atom,
        "scheme": atom,
        "conflict": atom
    }
    (where the scheme just happens to depict a conflict)
    Returns: a dict
    """
    if ((arg_text is not None or arg_id is not None) and (conflict_text is not None or conflict_id is not None)):

        if arg_text is not None:
            a = add_atom(arg_text)
        else:
            a = get_atom(arg_id)

        s = add_scheme("conflict")

        try:
            add_edge(s["id"], a["id"])
        except Exception as ex:
            print()
            ex
            raise Exception("Could not create new argument")

        if conflict_text is not None:
            c = add_atom(conflict_text)
        else:
            c = get_atom(conflict_id)

        try:
            add_edge(c["id"], s["id"])
        except Exception as ex:
            print()
            ex
            raise Exception("Could not create new argument")

        arg = {"argument": a, "scheme": s, "conflict": c}
        return arg
    return None


def add_edge(source_id, target_id):
    """
    Given a source atom ID & a target atom ID, create an
    edge linking the two and add it to the sadface doc,
    "sd" & return the dict representing the edge. If
    either of source or target IDs is invalid then an
    exception is raised.
    Returns: a dict
    """
    if ((get_node(source_id) is not None) and (get_node(target_id) is not None)):
        edge = new_edge(source_id, target_id)
        sd["edges"].append(edge)
        return edge
    raise Exception("Could not create new edge between: " + source_id + " & " + target_id)


def add_atom(text):
    """
    Create a new argument atom using the supplied text
    Returns: the new atom dict
    """
    atom = new_atom(text)
    sd["nodes"].append(atom)
    return atom


def add_atom_metadata(atom_id, key, value):
    """
    Add metadata, a key:value pair to the atom dict identified
    by the supplied atom ID.
    """
    for node in sd["nodes"]:
        if "atom" == node["type"]:
            if atom_id == node["id"]:
                node["metadata"][key] = value


def add_resource(content):
    """
    Create a new resource dict using the supplied content string
    then add to the resourses list of the sadface doc
    Returns: the new resource dict
    """
    res = new_resource(content)
    sd["resources"].append(res)
    return res


def add_resource_metadata(resource_id, key, value):
    """
    Add metadata, a key:value pair to the resource dict identified
    by the supplied atom ID.
    """
    for res in sd["resources"]:
        if res["id"] == resource_id:
            res["metadata"][key] = value


def add_sadface_metadata(key, value):
    """
    Add metadata, a key:value pair to the base sadface doc
    """
    sd["metadata"][key] = value


def add_scheme(name):
    """
    Add a new scheme node dict to the sadface document. The scheme type
    is identified by the supplied name
    Returns: The new scheme dict
    """
    scheme = new_scheme(name)
    sd["nodes"].append(scheme)
    return scheme


def add_source(atom_id, resource_id, text, offset, length):
    """
    Add a new source dict to the atom identified by the supplied
    atom ID. The new source refers to the an existing resource that
    is identified by the supplied resource ID. The source identifies
    text string in the resource dict that it references as well as
    the offset & length of the text from the beginning of the resource
    Returns: The new source dict
    """
    source = new_source(resource_id, text, offset, length)
    for node in sd["nodes"]:
        if "atom" == node["type"]:
            if atom_id == node["id"]:
                node["sources"].append(source)
                return source


def delete_atom(atom_id):
    """
    Remove the atom from the sadface document identified by the
    supplied atom ID
    """
    atom = get_atom(atom_id)
    sd["nodes"].remove(atom)


def delete_edge(edge_id):
    """
    Remove the edge from the sadface document identified by the
    supplied edge ID
    """
    edge = get_edge(edge_id)
    sd["edges"].remove(edge)


def delete_source(atom_id, resource_id):
    """
    Remove a source from the atom identified by the
    supplied atom ID & resource ID respectively
    """
    atom, resource = get_source(atom_id, resource_id)
    atom["sources"].remove(resource)


def delete_resource(resource_id):
    """
    Remove the resource from the sadface document identified by the
    supplied resource ID
    """
    resource = get_resource(resource_id)
    sd["resources"].remove(resource)


def delete_scheme(scheme_id):
    """
    Remove the schemee from the sadface document identified by the
    supplied scheme ID
    """
    scheme = get_scheme(scheme_id)
    sd["nodes"].remove(scheme)


def export_json():
    """
    Dump the current sadface document to a JSON string
    Returns: String-encoded JSON
    """
    return json.dumps(sd)


def export_dot():
    """
    Exports a subset of SADFace to the DOT graph description language
    Returns: String-encoded DOT document
    """
    max_length = 25
    edge_str = " -> "
    dot = "digraph SADFace {"
    dot += "node [style=\"filled\"]"
    for node in sd["nodes"]:
        if "text" in node:
            txt = node["text"]
            if len(txt) > max_length:
                txt = "\r\n".join(textwrap.wrap(txt, 25))
            line = '"{}"'.format(node['id']) + " [label=\"" + txt + "\"]" + " [shape=box, style=rounded];\n"
            dot += line
        elif "name" in node:
            line = '"{}"'.format(node['id']) + " [label=\"" + node["name"] + "\"]" + " [shape=diamond];\n"
            dot += line

    for edge in sd["edges"]:
        source = get_node(edge["source_id"])
        target = get_node(edge["target_id"])

        if ("atom" == source["type"]):
            dot += '"{}"'.format(source["id"])
        elif "scheme" == source["type"]:
            dot += '"{}"'.format(source["id"])

        dot += edge_str

        if ("atom" == target["type"]):
            dot += '"{}"'.format(target["id"])
        elif "scheme" == target["type"]:
            dot += '"{}"'.format(target["id"])

        dot += ";\n"

    dot += "}"

    return dot


def get_atom(atom_id):
    """
    Retrieve the atom dict identified by the supplied atom ID
    Returns: An atom dict
    """
    for node in sd["nodes"]:
        if atom_id == node["id"]:
            return node


def get_edge(edge_id):
    """
    Retrieve the edge dict identified by the supplied edge ID
    Returns: An edge dict
    """
    for edge in sd["edges"]:
        if edge_id == edge["id"]:
            return edge


def get_node(node_id):
    """
    Given a node's ID but no indication of node type, return the node if
    it exists or else indicate that it doesn't to the caller.
    Returns: A node dict or None
    """
    for node in sd["nodes"]:
        if node_id == node["id"]:
            return node


def get_resource(resource_id):
    """
    Retrieve the resource dict identified by the supplied resource ID
    Returns: An resource dict
    """
    for resource in sd["resources"]:
        if resource_id == resource["id"]:
            return resource


def get_scheme(scheme_id):
    """
    Retrieve the scheme dict identified by the supplied scheme ID
    Returns: An scheme dict
    """
    for node in sd["nodes"]:
        if scheme_id == node["id"]:
            return node


def get_source(atom_id, resource_id):
    """
    Retrieve the source dict identified by the supplied source ID
    Returns: An source dict
    """
    atom = get_atom(atom_id)
    for source in atom["sources"]:
        if resource_id == source["resource_id"]:
            return atom, source


def import_json(json_string):
    """
    Take a string-encoded JSON document and loads it into a Python dict
    Returns: the loaded dict
    """
    return json.loads(json_string)


def init():
    """
    Reads the config file from the supplied location then uses the data
    contained therein to personalise a new SADFace document
    Returns: A Python dict representing the new SADFace document
    """
    try:
        config.read(config_location)
    except:
        print()
        "Could not read configs from ", config_location
    return new_sadface()


def new_atom(text):
    """
    Creates a new SADFace atom node (Python dict) using the supplied text
    Returns: A Python dict representing the new SADFace atom
    """
    new_atom = {"id": new_uuid(), "type": "atom", "text": text, "sources": [], "metadata": {}}
    return new_atom


def new_edge(source_id, target_id):
    """
    Creates & returns a new edge dict using the supplied source &
    target IDs
    Returns: A Python dict representing the new edge
    """
    new_edge = {"id": new_uuid(), "source_id": source_id, "target_id": target_id}
    return new_edge


def new_sadface():
    """
    Creates & returns a new SADFace document
    Returns: A Python dict representing the new SADFace document
    """
    new_doc = {"id": new_uuid(), "analyst_name": config.get("analyst", "name"),
               "analyst_email": config.get("analyst", "email"), "created": now(), "edited": now(), "metadata": {},
               "resources": [], "nodes": [], "edges": []}
    return new_doc


def new_resource(content):
    """
    Given the supplied content (Python String), create a new resource dict
    Returns: A Python dict representing the new SADFace resource
    """
    new_resource = {"id": new_uuid(), "content": content, "type": "text", "metadata": {}}
    return new_resource


def new_scheme(name):
    """
    Create a new SADFace scheme (Python dict) using the supplied scheme name. The scheme
    name should refer to an existing scheme from a known schemeset
    Returns: A Python dict representing the new SADFace scheme
    """
    new_scheme = {"id": new_uuid(), "type": "scheme", "name": name}
    return new_scheme


def new_source(resource_id, text, offset, length):
    """
    Create a new SADFace source (Python dict) using the supplied resource ID (a source always
    refers to an existing resource) and identifying a section of text in the resource as well
    as an offset & segment length for locating the text in the original resource.
    Returns: A Python dict representing the new SADFace source
    """
    new_source = {"resource_id": resource_id, "text": text, "offset": offset, "length": length}
    return new_source


def new_uuid():
    """
    Utility method to generate a new universally unique ID. Used througout to uniquely
    identify various items such as atoms, schemes, resources, & edges
    Returns: A string
    """
    return str(uuid.uuid4())


def now():
    """
    Utility method to produce timestamps in ISO format without the microsecond
    portion, e.g. 2017-07-05T17:21:11
    Returns: A String
    """
    return datetime.datetime.now().replace(microsecond=0).isoformat()


def prettyprint(doc=None):
    """
    Print nicely formatted output of the passed in string or
    otherwise the SADFace document encoded as a String
    Returns: A String
    """
    string = sd
    if (doc is not None):
        string = doc
    return json.dumps(string, indent=4, sort_keys=True)


def save(filename=None, filetype="json"):
    """
    Write the prettyprinted SADFace document to a JSON file on disk
    """
    f = filename
    if filename is None:
        f = config.get("file", "name")
    f += "."
    f += filetype

    if ("dot" == filetype):
        with codecs.open(f, 'w', 'utf-8') as outfile:
            outfile.write(export_dot())
    else:
        with open(f, 'w') as outfile:
            json.dump(sd, outfile, codecs.getwriter('utf-8')(outfile), indent=4, sort_keys=True, ensure_ascii=False)


def update():
    """
    Updates the last edited timestamp for the SADFace doc to now
    """
    sd["edited"] = now()


def update_analyst(analyst):
    """
    Updates the name of the argument analyst in the SADFace doc to the supplied name
    """
    sd["analyst"] = analyst


def update_atom_text(atom_id, new_text):
    """
    An atoms text key:value pair is the canonical representation of a portion of text
    that exists in an argument. This should be updatable so that the overall document
    makes sense. Links to original source texts are maintained via the source list
    which indexes original text portions of linked resources.
    Returns: The updated atom dict
    """
    atom = get_atom(atom_id)
    if (atom is not None):
        atom["text"] = new_text
        return atom
    else:
        raise Exception("Could not update the text value for atom: " + atom_id)


def update_created(timestamp):
    """
    Updates the creation timestamp for the SADFace document to the supplied timestamp.
    This can be useful when moving analysed argument data between formats whilst
    maintaining original metadata.
    """
    sd["timestamp"] = timestamp


def update_id(id):
    """
    Update the SADFace document ID to match the supplied ID. This can be useful when
    moving analysed argument data between formats whilst maintaining original metadata.
    """
    sd["id"] = id


def update_edited(timestamp):
    """
    Update the last edited timestamp for the SADFace doc to match the supplied
    timestamp. This can be useful when moving analysed argument data between formats
    whilst maintaining original metadata.
    """
    sd["edited"] = timestamp


def update_scheme(scheme_id, scheme_name):
    """
    Given an ID for an existing scheme node, update the name associated with it and return the scheme node.

    Returns: Updated scheme dict
    """
    scheme = get_scheme(scheme_id)
    if (scheme is not None):
        scheme["name"] = scheme_name
        return scheme
    else:
        raise Exception("Could not update the name of scheme: " + scheme_id)


class REPL(cmd.Cmd):
    """
    The SADFace REPL. Type 'help' or 'help <command>' for assistance
    """

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = '> '
        self.intro = "The SADFace REPL. Type 'help' or 'help <command>' for assistance"
        REPL.do_init(self, None)

    def do_arg(self, line):
        """
        Arguments are depicted in the following fashion e.g. premise1,premise2~>conclusion
        premises are a comma separated list of strings where each string depicts a single
        premise. The conclusion is written at the end of the premise list using `~>` to
        indicate a defeasible Modus Ponens rule.
        The line is split initially on the '~>" to yield the premises (in the head)
        and the conclusion in the tail. The head is further split on the comma delimiters
        to retrieve each individual premise.
        """
        conid = None
        contxt = None
        if "~>" in line:
            head, tail = line.split("~>")
            if tail.startswith("id="):
                conid = tail.replace("id=", "")
            else:
                if (len(tail) > 0):
                    contxt = tail
            premtext = []
            premid = []
            for element in head.split(","):
                if element.startswith("id="):
                    premid.append(element.replace("id=", ""))
                else:
                    if (len(element) > 0):
                        premtext.append(element)
            if ((conid is not None or contxt is not None) and (premtext or premid)):
                arg = add_argument(con_text=contxt, prem_text=premtext, con_id=conid, prem_id=premid)
                print()
                arg
            else:
                print()
                "USAGE: arg premise,premise,...~>conclusion"
        else:
            print()
            "USAGE: arg premise,premise,...~>conclusion"

    def default(self, line):
        print()
        "I do not understand that command. Type 'help' for a list of commands."

    def do_add_resource(self, line):
        add_resource("hello world")
        print()
        prettyprint()

    def do_init(self, line):
        global sd
        sd = init()
        print()
        sd

    def do_print(self, line):
        print()
        sd

    def do_prettyprint(self, line):
        print()
        prettyprint()

    def do_save(self, line):
        if ('' != line):
            save(line)
        else:
            save()

    def do_quit(self, line):
        """
        Quit the SADRace REPL.
        """
        return True

    def emptyline(self):
        pass

    def help_init(self):
        print()
        "Creates a default SADFace document"

    do_p = do_print
    do_q = do_quit
    do_s = do_save
    do_pp = do_prettyprint


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This is the SADFace Python tool")
    parser.add_argument("-c", "--config", help="Supply a config file for SADFace to use.")
    parser.add_argument("-i", "--interactive", action="store_true", help="Use the SADFace REPL")
    parser.add_argument("-l", "--load", help="Load a JSON document into SADFace")
    args = parser.parse_args()

    if args.config:
        config_location = args.config

    if args.load:
        sd = import_json(args.load)
    else:
        if args.interactive:
            REPL().cmdloop()
        else:
            parser.print_help()
            sys.exit(0)