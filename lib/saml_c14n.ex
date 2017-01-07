defmodule Samelex.C14n do
  import SweetXml

  def strip(e) when elem(e,0) == :xmlDocument do
    new_kids = for k<-xmlDocument(e,:content) do
      if (elem(k,0) == :xmlElement) do strip(k) else k end
    end
    xmlDocument(e, content: new_kids)
  end
  def strip(e) when elem(e,0) == :xmlElement do
    new_kids = xmlElement(e,:content) |> Enum.filter(fn kid->
      if elem(kid,0) == :xmlElement do
        case canon_name(kid) do
          'http://www.w3.org/2000/09/xmldsig#Signature'-> false
          _name-> true
        end
      else
        true
      end
    end)
    xmlElement(e,content: new_kids)
  end

  def canon_name(ns, name, nsp) do
    ns_part = case ns do
      :empty-> xmlNamespace(nsp,:default)
      []-> xmlNamespace(nsp,:default)
      _->
         case Enum.into(xmlNamespace(nsp,:nodes),%{})[ns] do
           nil-> error({:ns_not_found,ns,nsp})
           uri-> '#{uri}'
         end
    end |> to_char_list
    name_part = to_char_list(name)
    List.flatten([ns_part | name_part])
  end

  def canon_name(e) when elem(e,0)==:xmlAttribute do
    case xmlAttribute(e,:nsinfo) do
      {ns,nme}-> canon_name(ns,nme,xmlAttribute(e,:namespace))
      _-> canon_name([],xmlAttribute(e,:name),xmlAttribute(e,:namespace))
    end
  end
  def canon_name(e) when elem(e,0)==:xmlElement do
    case xmlElement(e,:nsinfo) do
      {ns,nme}-> canon_name(ns,nme,xmlElement(e,:namespace))
      _-> canon_name([],xmlElement(e,:name),xmlElement(e,:namespace))
    end
  end

  def attr_lte(attra,attrb) do
    a = canon_name(attra); b = canon_name(attrb)
    prefixeda = match?({_,_},xmlAttribute(attra,:nsinfo))
    prefixedb = match?({_,_},xmlAttribute(attrb,:nsinfo))
    cond do
      prefixeda and !prefixedb-> false
      (!prefixeda) and prefixedb-> true
      true-> a <= b
    end
  end

  def clean_sort_attrs(attrs) do
    attrs
    |> Enum.filter(fn attr->
      case xmlAttribute(attr,:nsinfo) do
        {'xmlns',_}-> false
        _-> case xmlAttribute(attr,:name) do
          :xmlns-> false
          _-> true
        end
      end
    end)
    |> Enum.sort(&attr_lte(&1,&2))
  end

  def needed_ns(e,incl_ns) do
    needed_ns = case xmlElement(e,:nsinfo) do
      {nas,_}-> [nas]
      _-> []
    end
    Enum.reduce(xmlElement(e,:attributes),needed_ns, fn attr,needed->
      case xmlAttribute(attr,:nsinfo) do
        {'xmlns',prefix}->
          if prefix in incl_ns do [prefix | needed] else needed end
        {ns,_name}->
          if ns in needed do needed else [ns|needed] end
        _ -> needed
      end
    end)
  end

  def xml_safe_string(term), do: xml_safe_string(term,false)
  def xml_safe_string(term,quotes) when not is_list(term), do: xml_safe_string(to_char_list(term),quotes)
  def xml_safe_string([],_), do: []
  def xml_safe_string([next|rest],quotes) do
    cond do
      (!quotes and ([next] == '\n'))-> [next | xml_safe_string(rest,quotes)]
      next < 32 ->
        List.flatten(['&#x' ++ :erlang.integer_to_list(next,16) ++ ';' | xml_safe_string(rest,quotes)])
      quotes and ([next] == '"')-> 
        List.flatten(['&quot;'| xml_safe_string(rest, quotes)])
      ([next] == '&')->
        List.flatten(['&amp;'| xml_safe_string(rest, quotes)])
      ([next] == '<')->
        List.flatten(['&lt;'| xml_safe_string(rest, quotes)])
      (!quotes and ([next] == '>')) ->
        List.flatten(['&gt;' | xml_safe_string(rest, quotes)])
      true-> [next | xml_safe_string(rest,quotes)]
    end
  end
  def xml_safe_string(term, quotes), do:
    xml_safe_string('#{inspect term}',quotes)

  def c14n(e,_knownns,_activens,_comments,_inclns,acc) when elem(e,0) == :xmlText do
    [xml_safe_string(xmlText(e,:value)) | acc]
  end
  def c14n(e,_knownns,_activens,true,_inclns,acc) when elem(e,0) == :xmlComment do
    ['-->',xml_safe_string(xmlComment(e,:value)),'<!--' | acc]
  end
  def c14n(e,_knownns,_activens,_comments,_inclns,acc) when elem(e,0) == :xmlPI do
    name_str = '#{xmlPI(e,:name)}' |> :string.strip()
    case (e |> xmlPI(:value) |> :string.strip()) do
      []-> ['?>',name_str,'<?'|acc]
      _->  ['?>',xmlPI(e,:value), ' ', name_str, '<?' | acc]
    end
  end
  def c14n(e,knownns,activens,comments,inclns,acc) when elem(e,0) == :xmlDocument do
    acc = Enum.reduce(xmlDocument(e,:content),acc, fn kid, acc->
      case c14n(kid,knownns,activens,comments,inclns,acc) do
        ^acc-> acc
        other-> ['\n' | other]
      end
    end)
    case acc do
      ['\n' | rest]-> rest
      other-> other
    end
  end

  def c14n(e,_knownns,activens,_comments,_inclns,acc) when elem(e,0) == :xmlAttribute do
    case xmlAttribute(e,:nsinfo) do
      {ns,nname}->
        if ns in activens do
          ['"',xml_safe_string(xmlAttribute(e,:value),true),'="',nname,':',ns,' ' | acc]
        else
          error("attribute ns not active")
        end
      _-> ['"',xml_safe_string(xmlAttribute(e,:value),true),'="',to_char_list(xmlAttribute(e,:name)),' ' | acc]
    end
  end

  def c14n(e,knownns,activens,comments,inclns,acc) when elem(e,0) == :xmlElement do
    ns = xmlElement(e,:namespace)
    default = xmlNamespace(ns,:default)
    {activens,parent_default} = case activens do
      [{:default,p}|rest]-> {rest,p}
      other-> {other,''}
    end
    knownns = Enum.reduce(xmlNamespace(ns,:nodes),knownns, fn {ns,uri},nss->
      case :proplists.is_defined(ns,nss) do
        true->nss
        _-> [{ns,to_char_list(uri)} | nss]
      end
    end)
    needed_ns = needed_ns(e,inclns)
    attrs = clean_sort_attrs(xmlElement(e,:attributes))
    newns = needed_ns -- activens
    new_activens = activens ++ newns
    acc1 = case xmlElement(e,:nsinfo) do
      {ens,ename}-> [ename,':',ens,'<' | acc]
      _-> [to_char_list(xmlElement(e,:name)) ,'<' | acc]
    end
    {acc2, finaleactivens} = cond do
      not(default == []) and not(default == parent_default)->
        {['"',xml_safe_string(default,true),' xmlns="' | acc1],[{:default,default}|new_activens]}
      not(default == [])->
        {acc1,[{:default,default}|new_activens]}
      true->
        {acc1,new_activens}
    end
    acc3 = newns |> Enum.sort |> Enum.reduce(acc2,fn ns,accin->
      ['"',xml_safe_string(:proplists.get_value(ns,knownns,''),true), '="',ns,':',' xmlns' | accin]
    end)
    acc4 = attrs |> Enum.reduce(acc3,fn attr, accin->
      c14n(attr,knownns,finaleactivens,comments,inclns,accin)
    end)
    acc5 = ['>' | acc4]
    acc6 = Enum.reduce(xmlElement(e,:content),acc5, fn kid,accin->
      c14n(kid,knownns,finaleactivens,comments,inclns,accin)
    end)
    case xmlElement(e,:nsinfo) do
      {ns,name}->
        ['>',name,':',ns,'</' | acc6]
      _->
        ['>',to_char_list(xmlElement(e,:name)),'</' | acc6]
    end
  end

  def c14n(_,_,_,_,_,acc), do: acc

  # If the Comments argument is true, preserves comments in the output. Any
  # namespace prefixes listed in InclusiveNs will be left as they are and not
  # modified during canonicalization.
  def c14n(e), do: c14n(e,true)
  def c14n(e, comments), do: c14n(e,comments,[])
  def c14n(e,comments,incl_ns) do
    c14n(e,[],[],comments,incl_ns,[]) |> Enum.reverse |> List.flatten
  end

  def error(term) do
    throw term
  end
end
