package app

import (
	"os"
	"time"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/tendermint/tendermint/libs/log"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/context"
	sdk "github.com/cosmos/cosmos-sdk/types"
	wire "github.com/cosmos/cosmos-sdk/wire"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	"github.com/cosmos/cosmos-sdk/x/auth"
	abci "github.com/tendermint/tendermint/abci/types"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	eos "github.com/eoscanada/eos-go"
	"github.com/blockchain-develop/eosside/x/ibc"
)

const (
	FlagEosChainNode   = "eos-url"
)

type eostransfer struct {
	Id uint64 `json:"id"`
	From eos.AccountName `json:"from"`
	To eos.AccountName `json:"to"`
	Quantity eos.Asset  `json:"quantity"`
	Memo string `json:"memo"`
}

type sidereqcount struct {
	Id uint64 `json:"id"`
	G_index uint64 `json:"id"`
}

		
type transferaction struct {
	From        string `json:"from"`
	To          eos.AccountName `json:"to"`
	Quantity    eos.Asset `json:"quantity"`
	Memo        string `json:"memo"`
	Index       uint64 `json:"index"`
}

type relayCommander struct {
	cdc       *wire.Codec
	//address   sdk.AccAddress
	decoder   auth.AccountDecoder
	mainStore string
	ibcStore  string
	accStore  string

	logger log.Logger
}

// IBC relay command
func EosRelayCmd(cdc *wire.Codec) *cobra.Command {
	cmdr := relayCommander{
		cdc:       cdc,
		decoder:   authcmd.GetAccountDecoder(cdc),
		ibcStore:  "ibc",
		mainStore: "main",
		accStore:  "acc",

		logger: log.NewTMLogger(log.NewSyncWriter(os.Stdout)),
	}

	cmd := &cobra.Command{
		Use: "eosrelay",
		Run: cmdr.runEosRelay,
	}

	cmd.Flags().String(FlagEosChainNode, "http://localhost:8888", "<host>:<port>")
	cmd.MarkFlagRequired(FlagEosChainNode)
	viper.BindPFlag(FlagEosChainNode, cmd.Flags().Lookup(FlagEosChainNode))

	return cmd
}

// nolint: unparam
func (c relayCommander) runEosRelay(cmd *cobra.Command, args []string) {
	eosChainNode := viper.GetString(FlagEosChainNode)
	toChainID := viper.GetString(client.FlagChainID)
	toChainNode := viper.GetString(client.FlagNode)

	c.eosloop(eosChainNode, toChainID, toChainNode)
}

// This is nolinted as someone is in the process of refactoring this to remove the goto
// nolint: gocyclo
func (c relayCommander) eosloop(eosChainNode, toChainID, toChainNode string) {

	ctx := context.NewCoreContextFromViper()
	// get password
	passphrase, err := ctx.GetPassphraseFromStdin(ctx.FromAddressName)
	if err != nil {
		panic(err)
	}
	
	//
	eos_api := eos.New("http://127.0.0.1:8888")
	eos_info, _ := eos_api.GetInfo()
	c.logger.Info("eos info", "ServerVersion", eos_info.ServerVersion)
	c.logger.Info("eos info", "HeadBlockNum", eos_info.HeadBlockNum)

	ingressSequenceKey := ibc.IngressSequenceKey()

OUTER:
	for {
		time.Sleep(10 * time.Second)

		//
		ingressSequencebz, err := query(toChainNode, ingressSequenceKey, c.ibcStore)
		if err != nil {
			panic(err)
		}

		var ingressSequence int64
		if ingressSequencebz == nil {
			ingressSequence = 0
		} else if err = c.cdc.UnmarshalBinary(ingressSequencebz, &ingressSequence); err != nil {
			panic(err)
		}
		
		log := fmt.Sprintf("query chain : %s, ingress : %s, number : %d", toChainID, ingressSequenceKey, ingressSequence)
		c.logger.Info("log", "string", log)

		//
		gettable_request := eos.GetTableRowsRequest {
			Code: "pegzone",
			Scope: "pegzone",
			Table: "eostransfer",
			LowerBound: strconv.FormatInt(ingressSequence, 10),
		}

		gettable_response, eos_err := eos_api.GetTableRows(gettable_request)
		if eos_err != nil {
			c.logger.Info("eos get table failed", "error", eos_err)
			panic("eos get table failed")
		}

		c.logger.Info("eos get table successful", "result", gettable_response.Rows)
		
		//
		var eostransfers []*eostransfer
		err_json := gettable_response.BinaryToStructs(&eostransfers)
		if err_json != nil {
			c.logger.Info("eos get table failed", "error", err_json)
			panic("eos get table failed")
		}

		/*
		err_json := c.cdc.UnmarshalJSON(gettable_response.Rows, &transfers)
		if err_json != nil {
			panic("eos get table failed")
		}
		*/
		
		c.logger.Info("query chain table", "total", len(eostransfers))

		seq := (c.getSequence(toChainNode))
		//c.logger.Info("broadcast tx seq", "number", seq)

		for i, tran := range eostransfers {
			
			c.logger.Info("new eos transfer", "new", "xxxxxxx")
			c.logger.Info("eos transfer", "id", tran.Id)
			c.logger.Info("eos transfer", "from", tran.From)
			c.logger.Info("eos transfer", "to", tran.To)
			c.logger.Info("eos transfer", "quantity", tran.Quantity.String())
			c.logger.Info("eos transfer", "memo", tran.Memo)
			
			if tran.To != eos.AccountName("pegzone") {
				c.logger.Info("The To address is not pegzone", "error", "ignore")
				continue;
			}
			
			//
			from_eos := tran.From
			
			//
			to_addr := tran.Memo
			to_side, err := sdk.AccAddressFromBech32(to_addr)
			if err != nil {
				c.logger.Info("The eos side address is not valid", "error", "ignore")
				continue;
			}
			
			//
			coinsStr := tran.Quantity.String()
			coinsStr = strings.Replace(coinsStr, ".", "", -1)
			coins, err := sdk.ParseCoins(coinsStr)
			if err != nil {
				c.logger.Info("The coins format is not valid", "error", "ignore")
				continue;
			}
			
			// get the from address
			from, err := ctx.GetFromAddress()
			if err != nil {
				panic(err) 
			}

			//
			msg_side := ibc.EosTransferMsg{
				SrcAddr: string(from_eos),
				DestAddr: to_side,
				Coins: coins,
				Sequence: ingressSequence + int64(i),
				Relayer: from,
			}
			
			new_ctx := context.NewCoreContextFromViper().WithDecoder(authcmd.GetAccountDecoder(c.cdc)).WithSequence(int64(i))
			//ctx = ctx.WithNodeURI(viper.GetString(FlagHubChainNode))
			//ctx := context.NewCoreContextFromViper().WithDecoder(authcmd.GetAccountDecoder(c.cdc))
			new_ctx, err = new_ctx.Ensure(ctx.FromAddressName)
			new_ctx = new_ctx.WithSequence(seq)
			xx_res, err := new_ctx.SignAndBuild(ctx.FromAddressName, passphrase, []sdk.Msg{msg_side}, c.cdc)
			if err != nil {
				panic(err)
			}
			
			//
			err = c.broadcastTx(seq, toChainNode, xx_res)
			seq++
			if err != nil {
				c.logger.Error("error broadcasting ingress packet", "err", err)
				continue OUTER // TODO replace to break, will break first loop then send back to the beginning (aka OUTER)
			}

			c.logger.Info("Relayed IBC packet", "index", i)
		}
	}
}


// IBC relay command
func SideRelayCmd(cdc *wire.Codec) *cobra.Command {
	cmdr := relayCommander{
		cdc:       cdc,
		decoder:   authcmd.GetAccountDecoder(cdc),
		ibcStore:  "ibc",
		mainStore: "main",
		accStore:  "acc",

		logger: log.NewTMLogger(log.NewSyncWriter(os.Stdout)),
	}

	cmd := &cobra.Command{
		Use: "siderelay",
		Run: cmdr.runSideRelay,
	}

	cmd.Flags().String(FlagEosChainNode, "http://localhost:8888", "<host>:<port>")
	cmd.MarkFlagRequired(FlagEosChainNode)
	viper.BindPFlag(FlagEosChainNode, cmd.Flags().Lookup(FlagEosChainNode))

	return cmd
}

// nolint: unparam
func (c relayCommander) runSideRelay(cmd *cobra.Command, args []string) {
	eosChainNode := viper.GetString(FlagEosChainNode)
	fromChainID := viper.GetString(client.FlagChainID)
	fromChainNode := viper.GetString(client.FlagNode)

	c.sideloop(fromChainID, fromChainNode, eosChainNode)
}

// This is nolinted as someone is in the process of refactoring this to remove the goto
// nolint: gocyclo
func (c relayCommander) sideloop(fromChainID, fromChainNode, eosChainNode string) {
	
	//
	eos_api := eos.New("http://127.0.0.1:8888")
	eos_info, _ := eos_api.GetInfo()
	c.logger.Info("eos info", "ServerVersion", eos_info.ServerVersion)
	c.logger.Info("eos info", "HeadBlockNum", eos_info.HeadBlockNum)
	
	//
	wallet_api := eos.New("http://127.0.0.1:8900")
	wallet_api.WalletUnlock("default", "PW5J1TYPPsLmsz64AnZ7an5ujbgua1a81qbJpfMdVmefPy9NzJZz2")
	mySigner := eos.NewWalletSigner(wallet_api, "default")
	eos_err := mySigner.ImportPrivateKey("5KM1zpRKMrySAzgitoA3maTeMx12xsGvHdPVgrJXoYsM7hKFKxg")
	if eos_err != nil {
		//panic(eos_err)
	}
	eos_err = mySigner.ImportPrivateKey("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3")
	if eos_err != nil {
		//panic(eos_err)
	}
	
	//
	eos_api.SetSigner(mySigner)

	//
	egressSequenceKey := ibc.EgressSequenceKey()

OUTER:
	for {
		time.Sleep(10 * time.Second)

		//
		egressSequencebz, err := query(fromChainNode, egressSequenceKey, c.ibcStore)
		if err != nil {
			panic(err)
		}

		var egressSequence int64
		if egressSequencebz == nil {
			egressSequence = 0
		} else if err = c.cdc.UnmarshalBinary(egressSequencebz, &egressSequence); err != nil {
			panic(err)
		}
		
		log := fmt.Sprintf("query chain eos side, egress : %s, number : %d", egressSequenceKey, egressSequence)
		c.logger.Info("log", "string", log)
		
		
		//
		//
		gettable_request := eos.GetTableRowsRequest {
			Code: "pegzone",
			Scope: "pegzone",
			Table: "sidereqcount",
		}

		var index int64
		gettable_response, eos_err := eos_api.GetTableRows(gettable_request)
		if eos_err != nil {
			c.logger.Info("eos get table failed", "error", eos_err)
			//panic("eos get table failed")
			index = 0
		} else {

			c.logger.Info("eos get table successful", "result", gettable_response.Rows)
			
			//
			var sidereqcounts []*sidereqcount
			err_json := gettable_response.BinaryToStructs(&sidereqcounts)
			if err_json != nil {
				c.logger.Info("eos get table failed", "error", err_json)
				panic("eos get table failed")
			}
	
			/*
			err_json := c.cdc.UnmarshalJSON(gettable_response.Rows, &transfers)
			if err_json != nil {
				panic("eos get table failed")
			}
			*/
			
			c.logger.Info("query chain table", "total", len(sidereqcounts))
			
			//
			//var index int64
			if len(sidereqcounts) == 0 {
				index = 0
			} else {
				index = int64(sidereqcounts[0].G_index)
			}
		}
		
		//
		if egressSequence > index {
			c.logger.Info("Detected IBC packet", "total", egressSequence - index)
		}

	
		for i := index; i < egressSequence; i++ {
			
			//
			res, err := query(fromChainNode, ibc.EgressKey(i), c.ibcStore)
			if err != nil {
				c.logger.Error("error querying egress packet", "err", err)
				continue OUTER // TODO replace to break, will break first loop then send back to the beginning (aka OUTER)
			}
			
			//
			var sidetransfer_msg *ibc.SideTransferMsg
			err = c.cdc.UnmarshalBinary(res, &sidetransfer_msg)
			if err != nil {
				panic(err)
			}
			
			//
			coins_str := sidetransfer_msg.Coins.String()
			coin_symbol := coins_str[len(coins_str) - 3 :]
			coin_amount_1 := coins_str[:len(coins_str) - 3 - 4]
			
			coin_all := coin_amount_1 + ".0000 " + coin_symbol
			c.logger.Info("coin amount", "total", coin_all)
			
			quantity, err := eos.NewAsset(coin_all)
			if err != nil {
				panic(err)
			}
						
			//
			c.logger.Info("action", "coins", coin_all)
			c.logger.Info("action", "src", sidetransfer_msg.SrcAddr.String())
			c.logger.Info("action", "dest", sidetransfer_msg.DestAddr)
			
			action := &eos.Action {
				Account : eos.AN("pegzone"),
				Name: eos.ActN("transfer"),
				Authorization: []eos.PermissionLevel{
					{Actor: eos.AN("pegzone"), Permission: eos.PN("active")},
				},
				ActionData: eos.NewActionData(transferaction{
					From:     sidetransfer_msg.SrcAddr.String(),
					To:       eos.AN(sidetransfer_msg.DestAddr),
					Quantity: quantity,
					Memo:     "from eos side",
					Index:    uint64(i),
				}),
			}
			
			//
			eos_res, err := eos_api.SignPushActions(action)
			if err != nil {
				panic(err)
			}
			
			c.logger.Info("eos transfer result", "StatusCode", eos_res.StatusCode)
			c.logger.Info("eos transfer result", "TransactionID", eos_res.TransactionID)
			c.logger.Info("eos transfer result", "BlockID", eos_res.BlockID)
			c.logger.Info("eos transfer result", "BlockNum", eos_res.BlockNum)
			
			c.logger.Info("Relayed IBC packet", "index", i)
		}
	}
}


func (c relayCommander) getaddress() (addr sdk.AccAddress) {
	address, err := context.NewCoreContextFromViper().GetFromAddress()
	if err != nil {
		panic(err)
	}
	return address
}

func query(node string, key []byte, storeName string) (res []byte, err error) {
	return context.NewCoreContextFromViper().WithNodeURI(node).QueryStore(key, storeName)
}

func queryWithProof(node string, key []byte, storeName string) (x abci.ResponseQuery, err error) {
	return context.NewCoreContextFromViper().WithNodeURI(node).QueryStoreWithProof(key, storeName)
}

func commitWithProof(node string, height int64, storeName string) (x *ctypes.ResultCommit, err error) {
	return context.NewCoreContextFromViper().WithNodeURI(node).CommitWithProof(storeName, height)
}

func (c relayCommander) broadcastTx(seq int64, node string, tx []byte) error {
	_, err := context.NewCoreContextFromViper().WithNodeURI(node).WithSequence(seq + 1).BroadcastTx(tx)
	return err
}

func (c relayCommander) getSequence(node string) int64 {
	res, err := query(node, auth.AddressStoreKey(c.getaddress()), c.accStore)
	if err != nil {
		panic(err)
	}
	if nil != res {
		account, err := c.decoder(res)
		if err != nil {
			panic(err)
		}

		return account.GetSequence()
	}

	return 0
}
